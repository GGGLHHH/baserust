//! idm 的统一错误类型。**与 app 的 `AppError` 同形**:每变体映射 HTTP 状态码 + 机器码,
//! 原始细节只进日志、响应体只给安全消息。idm 独立跑时直接出 `ErrorBody`;被 app 用时
//! app 侧 `From<IdmError> for AppError` 把它接进应用错误体系 —— 错误**契约**(JSON 形状)
//! 共享、错误**类型**不绑死。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum IdmError {
    #[error("资源不存在")]
    NotFound,

    /// 业务校验失败(garde)。消息是为用户写的、安全的,可回传给客户端。
    #[error("请求无效: {0}")]
    Validation(String),

    /// 请求格式错误(body 非法 JSON 等)→ 400。内含原始提取错误,只进日志、不进响应体。
    #[error("请求格式错误")]
    BadRequest(String),

    /// 未认证 / 凭据无效 → 401。`client_message` 刻意通用,**绝不区分"用户不存在"与"密码错误"**(防枚举)。
    #[error("认证失败")]
    Unauthorized,

    /// 资源冲突(用户名/邮箱已占用)→ 409。消息写给用户、可回传。
    #[error("资源冲突: {0}")]
    Conflict(String),

    /// 兜底:任何 anyhow 错误(DB/IO/依赖)→ 500。原始 source chain 只进日志。
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IdmError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            IdmError::NotFound => StatusCode::NOT_FOUND,
            IdmError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            IdmError::BadRequest(_) => StatusCode::BAD_REQUEST,
            IdmError::Unauthorized => StatusCode::UNAUTHORIZED,
            IdmError::Conflict(_) => StatusCode::CONFLICT,
            IdmError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 机器可读错误类别 —— 前端按它分支,而非解析人读消息。
    pub fn code(&self) -> &'static str {
        match self {
            IdmError::NotFound => "not_found",
            IdmError::Validation(_) => "validation",
            IdmError::BadRequest(_) => "bad_request",
            IdmError::Unauthorized => "unauthorized",
            IdmError::Conflict(_) => "conflict",
            IdmError::Internal(_) => "internal",
        }
    }

    /// 进响应 `error` 字段的消息 —— 永远安全、刻意写。Unauthorized 刻意通用(防枚举)。
    pub fn client_message(&self) -> String {
        match self {
            IdmError::NotFound => "资源不存在".to_owned(),
            IdmError::Validation(msg) => format!("请求无效: {msg}"),
            IdmError::BadRequest(_) => "请求格式不正确".to_owned(),
            IdmError::Unauthorized => "认证失败".to_owned(),
            IdmError::Conflict(msg) => msg.clone(),
            IdmError::Internal(_) => "内部服务器错误".to_owned(),
        }
    }

    /// 响应里看不到、但排查需要的原始细节 → 进日志。`None` = 无额外细节。
    fn log_detail(&self) -> Option<String> {
        match self {
            IdmError::BadRequest(detail) => Some(detail.clone()),
            IdmError::Internal(err) => Some(format!("{err:?}")),
            IdmError::NotFound
            | IdmError::Validation(_)
            | IdmError::Unauthorized
            | IdmError::Conflict(_) => None,
        }
    }
}

/// 统一错误响应体(与 app 的 `ErrorBody` **同形**,前端 codegen 看到的错误形状一致)。
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    #[schema(value_type = String)]
    pub code: &'static str,
    pub error: String,
}

impl IntoResponse for IdmError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        if let Some(detail) = self.log_detail() {
            if status.is_server_error() {
                tracing::error!(code = self.code(), detail, "请求处理失败");
            } else {
                tracing::warn!(code = self.code(), detail, "请求被拒绝");
            }
        }
        let body = ErrorBody {
            code: self.code(),
            error: self.client_message(),
        };
        (status, Json(body)).into_response()
    }
}

/// garde 校验失败 → 422,让 service 能用 `?` 直接传播。
impl From<garde::Report> for IdmError {
    fn from(report: garde::Report) -> Self {
        IdmError::Validation(report.to_string())
    }
}
