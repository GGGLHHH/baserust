//! 自定义提取器:把 axum 默认的边界拒绝(纯文本 400)统一成 AppError 的 {code, error} 契约。
//! 业务 handler 用 `crate::infra::extract::{Path, Json, Query}` 替代 axum 同名提取器即可。
//!
//! 加新提取需求时照此包一层:调 axum 原提取器,失败分支映射进 AppError。

use axum::extract::{FromRequest, FromRequestParts, Path as AxumPath, Query as AxumQuery, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::Json as AxumJson;
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

/// 同名 `Json` 既是提取器(上面 FromRequest),也是响应体:委托 axum::Json 序列化。
/// 这样 handler 的参数和返回值都能统一用 `crate::infra::extract::Json`。
impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        AxumJson(self.0).into_response()
    }
}
