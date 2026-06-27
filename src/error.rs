use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// 应用统一错误类型。范式:
/// - 每个变体映射一个 HTTP 状态码(`status_code`)+ 一个机器可读 `code`。
/// - 业务/仓储层返回这个枚举;handler 用 `?` 传播,框架(`IntoResponse`)自动转 HTTP。
/// - 加错误种类 = 加变体 + 在 `status_code`/`code` 里各补一行。
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("资源不存在")]
    NotFound,

    #[error("请求无效: {0}")]
    Validation(String),

    /// 兜底:任何 anyhow 错误(DB、IO、依赖)→ 500。用 `?` 从 `anyhow::Error` 自动转入。
    /// 它的真实内容**绝不出网**,只进日志(见 `IntoResponse`)。
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 机器可读错误类别 —— 前端按它分支,而非脆弱地解析人读消息。
    fn code(&self) -> &'static str {
        match self {
            AppError::NotFound => "not_found",
            AppError::Validation(_) => "validation",
            AppError::Internal(_) => "internal",
        }
    }

    /// 对外消息。4xx 是客户端错误,回传具体原因(关于请求、不含内部);
    /// 5xx 一律通用文案,屏蔽 SQL/路径/依赖等内部细节。
    fn client_message(&self) -> String {
        match self {
            AppError::Internal(_) => "内部服务器错误".to_owned(),
            other => other.to_string(),
        }
    }
}

/// 统一错误响应体。错误必须统一成这个形状(成功响应可按资源各异,错误不行)。
#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 5xx 的真实错误只进日志(便于排障),绝不进响应体
        if let AppError::Internal(err) = &self {
            tracing::error!(error = ?err, "内部错误");
        }
        let body = ErrorBody {
            code: self.code(),
            error: self.client_message(),
        };
        (self.status_code(), Json(body)).into_response()
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
    fn internal_error_never_leaks_details() {
        // 模拟之前冒烟泄露的 sqlx 原文,确认对外消息不含任何内部细节
        let e = AppError::Internal(anyhow::anyhow!("relation \"widgets\" does not exist"));
        let msg = e.client_message();
        assert_eq!(msg, "内部服务器错误");
        assert!(!msg.contains("widgets"));
        assert!(!msg.contains("relation"));
        assert_eq!(e.code(), "internal");
    }

    #[test]
    fn client_errors_keep_their_detail() {
        assert_eq!(AppError::NotFound.client_message(), "资源不存在");
        let v = AppError::Validation("name 太短".to_owned());
        assert!(v.client_message().contains("name"));
        assert_eq!(v.code(), "validation");
    }
}
