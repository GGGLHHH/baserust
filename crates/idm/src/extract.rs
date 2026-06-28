//! idm 的 JSON 提取器:把 axum 默认的 body 拒绝(纯文本 400)统一成 `IdmError` 的 {code,error}。
//! idm 端点只需 JSON body 提取(无 Path/Query),故此处只有 `Json`。

use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use axum::Json as AxumJson;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::IdmError;

/// JSON body 提取器。失败(非法 JSON / content-type 不对)→ `IdmError::BadRequest`(400 + 统一 JSON)。
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = IdmError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match AxumJson::<T>::from_request(req, state).await {
            Ok(AxumJson(value)) => Ok(Self(value)),
            Err(rejection) => Err(IdmError::BadRequest(rejection.to_string())),
        }
    }
}

/// 同名 `Json` 既是提取器也是响应体:委托 axum::Json 序列化。
impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        AxumJson(self.0).into_response()
    }
}
