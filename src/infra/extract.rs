//! 自定义提取器:把 axum 默认的边界拒绝(纯文本 400)统一成 AppError 的 {code, error} 契约。
//! 业务 handler 用 `crate::infra::extract::{Path, Json, Query}` 替代 axum 同名提取器即可。
//!
//! 加新提取需求时照此包一层:调 axum 原提取器,失败分支映射进 AppError。

use axum::extract::{FromRequest, FromRequestParts, Path as AxumPath, Request};
// serde_html_form 基座:支持重复 key 解进 Vec(如 `?role=a&role=b`),serde_urlencoded 不能。
// 标量解析与 serde_urlencoded 等价,现有 13 处 Query<...> 调用点无感。
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::Json as AxumJson;
use axum_extra::extract::Query as AxumQuery;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::infra::error::AppError;

/// 路径参数提取器。失败(类型不匹配,如 `123` 不是 UUID)→ `AppError::BadRequest`(400 + 统一 JSON)。
pub struct Path<T>(pub T);

impl<T, S> FromRequestParts<S> for Path<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AxumPath::<T>::from_request_parts(parts, state).await {
            Ok(AxumPath(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::BadRequest(rejection.to_string())),
        }
    }
}

/// 查询参数提取器。失败(类型不匹配 / 反序列化失败)→ `AppError::BadRequest`。
pub struct Query<T>(pub T);

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AxumQuery::<T>::from_request_parts(parts, state).await {
            Ok(AxumQuery(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::BadRequest(rejection.to_string())),
        }
    }
}

/// JSON body 提取器。失败(body 不是合法 JSON / content-type 不对)→ `AppError::BadRequest`。
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match AxumJson::<T>::from_request(req, state).await {
            Ok(AxumJson(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::BadRequest(rejection.to_string())),
        }
    }
}

/// multipart 表单提取器。边界/Content-Type 拒绝(如 InvalidBoundary)→ `AppError::BadRequest`
/// (400 + 统一 JSON),不再漏 axum 的纯文本响应。字段级读取错误仍由 handler 逐字段处理。
pub struct Multipart(pub axum::extract::Multipart);

impl<S> FromRequest<S> for Multipart
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Multipart::from_request(req, state).await {
            Ok(mp) => Ok(Self(mp)),
            Err(rejection) => Err(AppError::BadRequest(rejection.to_string())),
        }
    }
}

/// multipart 里第一个 `file` 部分(文件名 / MIME / 字节)。
pub struct FilePart {
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub data: bytes::Bytes,
}

/// 读出 multipart 中名为 `file` 的部分,排空其余部分(推进流)。
/// 无 `file` 部分 → `Ok(None)`(调用方按自己的语义回 422);读取失败 → 400。
/// 单文件表单(如头像上传)直接用;多字段表单(如 contents/upload)仍手写循环。
pub async fn file_part(
    multipart: &mut axum::extract::Multipart,
) -> Result<Option<FilePart>, AppError> {
    let mut out = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        if field.name() == Some("file") && out.is_none() {
            let file_name = field.file_name().map(str::to_owned);
            let mime_type = field.content_type().map(str::to_owned);
            let data = field
                .bytes()
                .await
                .map_err(|e| AppError::BadRequest(e.to_string()))?;
            out = Some(FilePart {
                file_name,
                mime_type,
                data,
            });
        } else {
            let _ = field.bytes().await; // 未知/重复部分:读掉推进流
        }
    }
    Ok(out)
}

/// 同名 `Json` 既是提取器(上面 FromRequest),也是响应体:委托 axum::Json 序列化。
/// 这样 handler 的参数和返回值都能统一用 `crate::infra::extract::Json`。
impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        AxumJson(self.0).into_response()
    }
}
