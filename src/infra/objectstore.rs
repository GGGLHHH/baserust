//! minio/S3 对象存储后端 —— content 库 `ObjectStore` blob 端口的**生产实现**(归 app)。
//!
//! content 库零外部依赖、默认 `InMemoryObjectStore`;真正的 minio/S3 接线是 app 的关注点,经
//! `ContentService::new(..., store, backend_name)` 注入。设了 `S3_ENDPOINT` 才用本实现(见 `app::state`)。
//!
//! **不泄露契约**:任何 SDK 故障 → `ContentError::Storage(anyhow)`,原始细节(含 key/bucket/backend)
//! 只活在 anyhow 的 source,经 `AppError::Internal` 落日志,**绝不进响应体**。

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use bytes::Bytes;
use time::OffsetDateTime;

use content::{ContentError, ObjectMeta, ObjectStore, UploadParams};

/// minio/S3 后端。`Client` 内部是 Arc(廉价 Clone),`bucket` 是落字节的桶名。
pub struct S3ObjectStore {
    client: Client,
    bucket: String,
}

impl S3ObjectStore {
    /// 建 minio/S3 客户端:显式 endpoint + region + **静态凭据** + `force_path_style(true)`
    /// (minio 必须走 path-style,否则 SDK 默认 vhost-style 解析不到桶)。
    /// 凭据从 config 显式给(不走 SDK 的环境/profile 默认链)——脚手架要可控、可零环境变量复现。
    pub async fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Self {
        let creds = Credentials::new(access_key, secret_key, None, None, "static");
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .endpoint_url(endpoint)
            .credentials_provider(creds)
            .load()
            .await;
        // force_path_style 是 S3 专属设置,只能落 s3 的 Config builder(不在通用 aws_config 上)。
        let conf = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(conf),
            bucket: bucket.to_owned(),
        }
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn upload(&self, params: UploadParams, data: Bytes) -> Result<(), ContentError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&params.object_key)
            .body(ByteStream::from(data.to_vec()));
        if let Some(ct) = &params.mime_type {
            req = req.content_type(ct);
        }
        if let Some(name) = &params.file_name {
            // 原始文件名进 Content-Disposition(下载时供浏览器命名);引号转义防注入。
            req = req.content_disposition(format!(
                "attachment; filename=\"{}\"",
                name.replace('"', "")
            ));
        }
        req.send().await.map_err(store_err)?;
        Ok(())
    }

    async fn download(&self, object_key: &str) -> Result<Bytes, ContentError> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(store_err)?;
        let agg = out.body.collect().await.map_err(store_err)?;
        Ok(agg.into_bytes())
    }

    async fn delete(&self, object_key: &str) -> Result<(), ContentError> {
        // S3 delete 对不存在的 key 也返成功 → 天然幂等(对齐端口契约)。
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn object_meta(&self, object_key: &str) -> Result<ObjectMeta, ContentError> {
        let head = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(store_err)?;
        Ok(ObjectMeta {
            key: object_key.to_owned(),
            size: head.content_length().unwrap_or(0),
            content_type: head.content_type().map(str::to_owned),
            etag: head.e_tag().map(str::to_owned),
            updated_at: head
                .last_modified()
                .and_then(|dt| OffsetDateTime::from_unix_timestamp(dt.secs()).ok()),
        })
    }
}

/// 任意 SDK 错误 → `ContentError::Storage`。原始错误作为 anyhow source 保留(key/bucket 细节随之),
/// 经 `AppError::Internal` 只落日志,响应体只给通用 500 文案。
fn store_err<E>(e: E) -> ContentError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ContentError::Storage(anyhow::Error::new(e))
}
