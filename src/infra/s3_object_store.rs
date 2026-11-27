//! minio/S3 对象存储后端 —— content 库 `ObjectStore` blob 端口的**生产实现**(归 app)。
//!
//! content 库零外部依赖、默认 `InMemoryObjectStore`;真正的 minio/S3 接线是 app 的关注点,经
//! `ContentService::new(..., store, backend_name)` 注入。设了 `S3_ENDPOINT` 才用本实现(见 `app::app_state`)。
//!
//! **不泄露契约**:任何 SDK 故障 → `ContentError::Storage(anyhow)`,原始细节(含 key/bucket/backend)
//! 只活在 anyhow 的 source,经 `AppError::Internal` 落日志,**绝不进响应体**。

use std::error::Error;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Builder as S3ConfigBuilder, Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use bytes::Bytes;
use content::{ContentError, ObjectStore, StoredObjectMetadata, UploadRequest};
use time::OffsetDateTime;

use crate::infra::percent;

/// presigned URL 有效期。短:URL 是临时授权(拿到即可访问),`/preview`、`/download` 每次 307 现签,
/// 客户端从不存它 —— 稳定 URL 是 app 端点,签名 URL 只活在一次跳转里。
const PRESIGN_TTL: Duration = Duration::from_secs(300);

/// 直传(PUT)凭证有效期。比跳转凭证(300s)长得多:客户端拿到后要真传字节,
/// 大文件/慢网络 5 分钟不够;1h 是"够传完、又不至于长期裸奔"的折中。
/// 暴露面(教学点):凭证持有者在整个 TTL 内可**反复覆写该 key —— 包括 confirm 之后**,
/// 届时 confirm 时记的 size/etag 变陈旧、preview/download 会吐换过的字节。
/// 收紧路径:confirm 钉 ETag 校验 / 缩短 TTL / 一次性 key。脚手架接受现状。
const PRESIGN_UPLOAD_TTL: Duration = Duration::from_secs(3600);

/// minio/S3 后端。`Client` 内部是 Arc(廉价 Clone),`bucket` 是落字节的桶名。
/// `presign_relative`:presign 出的 URL 是否剥 host 成相对(见 [`Self::finalize`])。
pub struct S3ObjectStore {
    client: Client,
    bucket: String,
    presign_relative: bool,
}

/// presign URL 的形态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresignUrlStyle {
    /// 绝对 URL(dev / 直连 minio,host 来自 endpoint)。
    Absolute,
    /// 剥掉 host 的相对 URL(prod 边缘 TLS 拓扑,浏览器经 nginx→minio,零域名配置)。
    Relative,
}

/// [`S3ObjectStore::new`] 的连接参数(凭据从 config 显式给)。
#[derive(Clone, Copy)]
pub struct S3Settings<'config> {
    pub endpoint: &'config str,
    pub region: &'config str,
    pub bucket: &'config str,
    pub access_key: &'config str,
    pub secret_key: &'config str,
    pub presign_url_style: PresignUrlStyle,
}

impl S3ObjectStore {
    /// 建 minio/S3 客户端:显式 endpoint + region + **静态凭据** + `force_path_style(true)`
    /// (minio 必须走 path-style,否则 SDK 默认 vhost-style 解析不到桶)。
    /// 凭据从 config 显式给(不走 SDK 的环境/profile 默认链)——脚手架要可控、可零环境变量复现。
    /// `presign_url_style` 见 [`PresignUrlStyle`]。
    pub async fn new(settings: S3Settings<'_>) -> Self {
        let S3Settings {
            endpoint,
            region,
            bucket,
            access_key,
            secret_key,
            presign_url_style,
        } = settings;
        let credentials = Credentials::new(access_key, secret_key, None, None, "static");
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .endpoint_url(endpoint)
            .credentials_provider(credentials)
            .load()
            .await;
        // force_path_style 是 S3 专属设置,只能落 s3 的 Config builder(不在通用 aws_config 上)。
        let s3_config = S3ConfigBuilder::from(&shared)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(s3_config),
            bucket: bucket.to_owned(),
            presign_relative: presign_url_style == PresignUrlStyle::Relative,
        }
    }

    /// presign URL 定形。relative 模式剥 `scheme://host`,只留 `/<bucket>/<key>?X-Amz-...`——
    /// 签名只覆盖 host 值本身(不覆盖"URL 里写没写 host"),故剥 host 不破签名;反代把 Host 固定回
    /// 签名 host(= `S3_ENDPOINT`)即验签通过。浏览器按 origin 解析相对路径,容器全程不知域名。
    fn finalize(&self, url: String) -> String {
        if !self.presign_relative {
            return url;
        }
        // scheme://host[:port]/path?query → /path?query(找 "://" 后第一个 '/')。
        let relative = url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|slash| rest[slash..].to_owned()));
        match relative {
            Some(relative) => relative,
            None => url, // 无预期形状:原样(presigned 总是 scheme://host/bucket/key,不该走到)
        }
    }

    /// 共用 presign GET:disposition 差异(inline vs attachment)就是 preview/download 的领域区别。
    /// 纯客户端 HMAC 计算,不打网络;签名含 Host —— `S3_ENDPOINT` 必须浏览器可达(单域名前提,见 compose)。
    /// 已知不一致(接受):presign 只 override disposition,不带 response-content-type ——
    /// S3 用对象上传时自带的 Content-Type;后期 PUT /metadata 改 mime 只影响代理分支。
    /// 要一致:库端口 *_url 加 mime 参数(v0.3 再说,现有用例上传时 mime 即正确)。
    async fn presign_get(
        &self,
        object_key: &str,
        disposition: String,
    ) -> Result<Option<String>, ContentError> {
        let presigning = PresigningConfig::expires_in(PRESIGN_TTL).map_err(storage_error)?;
        let signed = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .response_content_disposition(disposition)
            .presigned(presigning)
            .await
            .map_err(storage_error)?;
        Ok(Some(self.finalize(signed.uri().to_string())))
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn upload(&self, request: UploadRequest, data: Bytes) -> Result<(), ContentError> {
        let mut put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&request.object_key)
            .body(ByteStream::from(data)); // Bytes 已 owned,直接喂,免整块复制
        if let Some(mime) = &request.mime_type {
            put = put.content_type(mime);
        }
        if let Some(name) = &request.file_name {
            // 原始文件名进 Content-Disposition(下载时供浏览器命名):RFC 6266,ascii 兜底 + filename*
            // 承载非 ASCII/控制字符/引号(裸插值会乱码或注入),与 download_url / 代理下载路径同口径。
            put = put.content_disposition(percent::content_disposition_attachment(name));
        }
        put.send().await.map_err(storage_error)?;
        Ok(())
    }

    async fn download(&self, object_key: &str) -> Result<Bytes, ContentError> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(storage_error)?;
        let aggregated = object.body.collect().await.map_err(storage_error)?;
        Ok(aggregated.into_bytes())
    }

    async fn delete(&self, object_key: &str) -> Result<(), ContentError> {
        // S3 delete 对不存在的 key 也返成功 → 天然幂等(对齐端口契约)。
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    /// 直传凭证(presigned PUT)。`mime_type` 给了就签进凭证(S3 把 Content-Type 纳入签名,
    /// 客户端 PUT 带不一样的头 → 403)—— 两步上传没有"写入前校验",这是唯一提前钉住的约束。
    async fn upload_url(
        &self,
        object_key: &str,
        mime_type: Option<&str>,
    ) -> Result<Option<String>, ContentError> {
        let presigning = PresigningConfig::expires_in(PRESIGN_UPLOAD_TTL).map_err(storage_error)?;
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(object_key);
        if let Some(mime) = mime_type {
            request = request.content_type(mime);
        }
        let signed = request.presigned(presigning).await.map_err(storage_error)?;
        Ok(Some(self.finalize(signed.uri().to_string())))
    }

    /// 预签名下载 URL(attachment;filename 由 service 层按"metadata 优先"决议好传入)。
    async fn download_url(
        &self,
        object_key: &str,
        download_filename: Option<&str>,
    ) -> Result<Option<String>, ContentError> {
        let disposition = match download_filename {
            // RFC 6266(ascii 兜底 + filename*),同 upload 侧 / 代理下载路径 —— 见 percent::content_disposition_attachment。
            Some(name) => percent::content_disposition_attachment(name),
            None => "attachment".to_owned(),
        };
        self.presign_get(object_key, disposition).await
    }

    /// 预签名预览 URL(inline —— 浏览器直接渲染,`<img>`/`<video>` 友好)。
    async fn preview_url(&self, object_key: &str) -> Result<Option<String>, ContentError> {
        self.presign_get(object_key, "inline".to_owned()).await
    }

    async fn metadata(&self, object_key: &str) -> Result<StoredObjectMetadata, ContentError> {
        let head = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(storage_error)?;
        let mut metadata =
            StoredObjectMetadata::new(object_key.to_owned(), head.content_length().unwrap_or(0));
        metadata.content_type = head.content_type().map(str::to_owned);
        metadata.etag = head.e_tag().map(str::to_owned);
        metadata.updated_at = head
            .last_modified()
            .and_then(|modified| OffsetDateTime::from_unix_timestamp(modified.secs()).ok());
        Ok(metadata)
    }
}

/// 任意 SDK 错误 → `ContentError::Storage`。原始错误作为 anyhow source 保留(key/bucket 细节随之),
/// 经 `AppError::Internal` 只落日志,响应体只给通用 500 文案。
fn storage_error<E>(error: E) -> ContentError
where
    E: Error + Send + Sync + 'static,
{
    ContentError::Storage(anyhow::Error::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// presign 是纯客户端 HMAC 计算(不打网络)→ 离线断言 URL 形状:
    /// host 来自 S3_ENDPOINT(单域名前提)、带签名参数、disposition 区分两方法。
    #[tokio::test]
    async fn presign_urls_carry_host_signature_and_disposition() {
        let store = S3ObjectStore::new(S3Settings {
            endpoint: "http://localhost:9862",
            region: "us-east-1",
            bucket: "content",
            access_key: "minio",
            secret_key: "minio12345",
            presign_url_style: PresignUrlStyle::Absolute, // host 来自 endpoint
        })
        .await;
        let download = store
            .download_url("k1/k2", Some("报表 \"final\".pdf"))
            .await
            .unwrap()
            .expect("S3 后端应支持 presign");
        assert!(
            download.starts_with("http://localhost:9862/content/k1/k2?"),
            "{download}"
        );
        assert!(download.contains("X-Amz-Signature="), "{download}");
        assert!(
            download.contains("response-content-disposition=attachment"),
            "{download}"
        );
        // RFC 6266:filename*(UTF-8 承载真实名)签进 disposition(SigV4 把 '*' 编成 %2A);
        // filename= 的 ascii 兜底把非 ASCII/引号净化成 '_',不裸反射。
        assert!(
            download.contains("filename%2A"),
            "应带 RFC 6266 filename*: {download}"
        );
        assert!(
            download.contains("X-Amz-Expires=300"),
            "TTL 应钉在 300s: {download}"
        );

        let preview = store.preview_url("k1/k2").await.unwrap().unwrap();
        assert!(
            preview.contains("response-content-disposition=inline"),
            "{preview}"
        );

        // 直传凭证(PUT):独立 TTL 3600s;给了 mime → content-type 签进凭证(SignedHeaders 可见),
        // 客户端 PUT 必须带同样的头 —— 类型声明跑不掉。
        let upload = store
            .upload_url("k1/k2", Some("image/png"))
            .await
            .unwrap()
            .expect("S3 后端应支持直传凭证");
        assert!(
            upload.starts_with("http://localhost:9862/content/k1/k2?"),
            "{upload}"
        );
        assert!(upload.contains("X-Amz-Expires=3600"), "{upload}");
        assert!(
            upload.contains("content-type") && upload.contains("X-Amz-SignedHeaders="),
            "mime 应签进凭证: {upload}"
        );
        // 无 mime:凭证照签,只是不钉 content-type。
        assert!(store.upload_url("k1/k2", None).await.unwrap().is_some());
    }

    /// relative 模式:presign URL 剥 host,只留 `/<bucket>/<key>?...`——浏览器经反代→minio,零域名。
    /// 签名/disposition/TTL 仍在(剥 host 不破签名:反代把 Host 固定回签名 host 即验签通过)。
    #[tokio::test]
    async fn relative_presign_strips_host_keeps_signature() {
        let store = S3ObjectStore::new(S3Settings {
            endpoint: "http://minio:9000", // 内网 host:签名用它,反代把 Host 固定回它
            region: "us-east-1",
            bucket: "content",
            access_key: "minio",
            secret_key: "minio12345",
            presign_url_style: PresignUrlStyle::Relative,
        })
        .await;
        let download = store
            .download_url("k1/k2", Some("f.pdf"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            download.starts_with("/content/k1/k2?"),
            "应是相对路径,无 scheme/host: {download}"
        );
        assert!(
            !download.contains("minio:9000"),
            "不该含内网 host: {download}"
        );
        assert!(!download.contains("://"), "不该含 scheme: {download}");
        assert!(
            download.contains("X-Amz-Signature="),
            "签名仍在: {download}"
        );
        assert!(
            download.contains("response-content-disposition=attachment"),
            "{download}"
        );

        let upload = store
            .upload_url("k1/k2", Some("image/png"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            upload.starts_with("/content/k1/k2?"),
            "直传凭证也相对: {upload}"
        );
        assert!(upload.contains("X-Amz-SignedHeaders="), "{upload}");

        let preview = store.preview_url("k1/k2").await.unwrap().unwrap();
        assert!(preview.starts_with("/content/k1/k2?"), "{preview}");
        assert!(
            preview.contains("response-content-disposition=inline"),
            "{preview}"
        );
    }
}
