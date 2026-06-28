use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

/// 应用统一错误类型。范式:
/// - 每个变体映射 HTTP 状态码(`status_code`)+ 机器码(`code`)。
/// - 业务/仓储层返回它;handler 用 `?` 传播,`IntoResponse` 自动转 HTTP。
///
/// **统一错误契约(关键)**:任何携带底层原始错误的变体,原始细节只进**日志**
/// (`log_detail`),响应体只给刻意写的**安全消息**(`client_message`)。不管来源是
/// uuid 解析、sqlx、还是 io,都绝不会把原始措辞漏给客户端 —— 加新错误来源时只要走
/// 这套契约,就天然不泄露。加错误种类 = 加变体 + 在下面四个 match 各补一行。
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("资源不存在")]
    NotFound,

    /// 业务校验失败(garde)。消息是为用户写的、安全的,可回传给客户端。
    #[error("请求无效: {0}")]
    Validation(String),

    /// 请求格式错误(路径参数类型不匹配、body 非法 JSON 等)→ 400。
    /// 内含的字符串是**原始提取错误**(库措辞),只进日志、不进响应体。
    #[error("请求格式错误")]
    BadRequest(String),

    /// 未认证 / 凭据无效(登录失败、token 无效或过期、改密旧密码错)→ 401。
    /// `client_message` 刻意通用,**绝不区分"用户不存在"与"密码错误"**(防账号枚举)。
    #[error("认证失败")]
    Unauthorized,

    /// 资源冲突(注册时 email 已占用)→ 409。消息写给用户、可回传(不含内部措辞)。
    #[error("资源冲突: {0}")]
    Conflict(String),

    /// 兜底:任何 anyhow 错误(DB、IO、依赖)→ 500。原始 source chain 只进日志。
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 机器可读错误类别 —— 前端按它分支,而非脆弱地解析人读消息。
    fn code(&self) -> &'static str {
        match self {
            AppError::NotFound => "not_found",
            AppError::Validation(_) => "validation",
            AppError::BadRequest(_) => "bad_request",
            AppError::Unauthorized => "unauthorized",
            AppError::Conflict(_) => "conflict",
            AppError::Internal(_) => "internal",
        }
    }

    /// 进响应 `error` 字段的消息 —— **永远安全、刻意写**,绝不含底层库的原始措辞。
    /// Validation/Conflict 回传"具体内容"(本就写给用户);Unauthorized 刻意通用(防枚举)。
    fn client_message(&self) -> String {
        match self {
            AppError::NotFound => "资源不存在".to_owned(),
            AppError::Validation(msg) => format!("请求无效: {msg}"),
            AppError::BadRequest(_) => "请求格式不正确".to_owned(),
            AppError::Unauthorized => "认证失败".to_owned(),
            AppError::Conflict(msg) => msg.clone(),
            AppError::Internal(_) => "内部服务器错误".to_owned(),
        }
    }

    /// 响应里看不到、但排查需要的**原始细节** → 进日志。`None` = 无额外细节。
    /// 这是"原始错误一律落日志"的统一入口:BadRequest 落 rejection、Internal 落
    /// anyhow 的完整 source chain;将来 sqlx/io 错误经 `?` 进 Internal 也自动落这里。
    fn log_detail(&self) -> Option<String> {
        match self {
            AppError::BadRequest(detail) => Some(detail.clone()),
            AppError::Internal(err) => Some(format!("{err:?}")),
            AppError::NotFound
            | AppError::Validation(_)
            | AppError::Unauthorized
            | AppError::Conflict(_) => None,
        }
    }
}

/// 统一错误响应体。pub + ToSchema:让这个契约出现在 OpenAPI,前端 codegen 能看到错误形状。
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    /// 机器可读错误类别(not_found / validation / bad_request / unauthorized / conflict / internal)
    #[schema(value_type = String)]
    pub code: &'static str,
    /// 给人看的安全消息 —— 不含 SQL/解析器/路径等任何内部原始措辞
    pub error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        // 统一:任何带原始细节的错误都把原始内容写进日志(响应体永远看不到它)。
        // 5xx 用 error、4xx 用 warn。日志在请求的 http span 内,自动带 request_id 可关联。
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
impl From<garde::Report> for AppError {
    fn from(report: garde::Report) -> Self {
        AppError::Validation(report.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_detail_goes_to_log_never_to_response() {
        // BadRequest:库原始措辞(uuid 解析失败)进日志,响应只给安全文案
        let e = AppError::BadRequest("Cannot parse `id`: UUID parsing failed".to_owned());
        assert_eq!(e.client_message(), "请求格式不正确");
        assert!(!e.client_message().contains("UUID"));
        assert!(e.log_detail().unwrap().contains("UUID"));

        // Internal(将来 sqlx 错误同理):原始 SQL 进日志,响应只给通用文案
        let e = AppError::Internal(anyhow::anyhow!("relation \"widgets\" does not exist"));
        assert_eq!(e.client_message(), "内部服务器错误");
        assert!(!e.client_message().contains("widgets"));
        assert!(e.log_detail().unwrap().contains("widgets"));
        assert_eq!(e.code(), "internal");
    }

    #[test]
    fn client_facing_errors_keep_useful_message() {
        // NotFound / Validation 是写给客户端的,可回传;且无需额外日志细节
        assert_eq!(AppError::NotFound.client_message(), "资源不存在");
        assert!(AppError::NotFound.log_detail().is_none());

        let v = AppError::Validation("name: length is lower than 1".to_owned());
        assert!(v.client_message().contains("name"));
        assert!(v.log_detail().is_none());
        assert_eq!(v.code(), "validation");
    }

    #[test]
    fn unauthorized_is_generic_to_prevent_enumeration() {
        // 401 文案必须通用:不暴露"是用户不存在还是密码错" —— 防账号枚举
        let e = AppError::Unauthorized;
        assert_eq!(e.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(e.code(), "unauthorized");
        assert_eq!(e.client_message(), "认证失败");
        assert!(e.log_detail().is_none());

        // Conflict:409,消息写给用户、可回传
        let c = AppError::Conflict("该邮箱已被注册".to_owned());
        assert_eq!(c.status_code(), StatusCode::CONFLICT);
        assert_eq!(c.code(), "conflict");
        assert_eq!(c.client_message(), "该邮箱已被注册");
    }
}
