//! 核心错误 [`AppError`] 的 **HTTP 适配**:变体 → 状态码 / 机器码 / 安全消息 / 落日志,
//! 以及统一错误响应体 `ErrorBody`。核心(`kernel::error`)只表达业务语义,不知道 HTTP。
//!
//! **统一错误契约(关键)**:任何携带底层原始错误的变体,原始细节只进**日志**
//! (`log_detail`),响应体只给刻意写的**安全消息**(`client_message`)。不管来源是
//! uuid 解析、sqlx、还是 io,都绝不会把原始措辞漏给客户端 —— 加新错误来源时只要走
//! 这套契约,就天然不泄露。加错误种类 = 在 `kernel::error` 加变体 + 在下面四个 match 各补一行。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use crate::kernel::error::AppError;

/// 核心错误的 **HTTP 映射**(状态码 / 机器码 / 安全消息 / 落日志)。`AppError` 在核心 crate,孤儿规则
/// 不许在这里给它写固有方法 —— 用扩展 trait 承载。
pub trait HttpErrorExt {
    fn status_code(&self) -> StatusCode;
    fn code(&self) -> ErrorCode;
    fn client_message(&self) -> String;
    fn log_detail(&self) -> Option<String>;
}

impl HttpErrorExt for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound | AppError::AccountNotFound => StatusCode::NOT_FOUND,
            AppError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized | AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Forbidden | AppError::TenantRequired => StatusCode::FORBIDDEN,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 机器可读错误类别 —— 前端按它分支,而非脆弱地解析人读消息。
    fn code(&self) -> ErrorCode {
        match self {
            AppError::NotFound => ErrorCode::NotFound,
            AppError::AccountNotFound => ErrorCode::AccountNotFound,
            AppError::Validation(_) => ErrorCode::Validation,
            AppError::BadRequest(_) => ErrorCode::BadRequest,
            AppError::Unauthorized => ErrorCode::Unauthorized,
            AppError::InvalidCredentials => ErrorCode::InvalidCredentials,
            AppError::Conflict(_) => ErrorCode::Conflict,
            AppError::Forbidden => ErrorCode::Forbidden,
            AppError::TenantRequired => ErrorCode::TenantRequired,
            AppError::Internal(_) => ErrorCode::Internal,
        }
    }

    /// 进响应 `error` 字段的消息 —— **永远安全、刻意写**,绝不含底层库的原始措辞。
    /// Validation/Conflict 回传"具体内容"(本就写给用户);Unauthorized / InvalidCredentials 刻意通用(防枚举)。
    fn client_message(&self) -> String {
        match self {
            AppError::NotFound => "Resource not found".to_owned(),
            AppError::AccountNotFound => "Account not found".to_owned(),
            AppError::Validation(msg) => format!("Invalid request: {msg}"),
            AppError::BadRequest(_) => "Malformed request".to_owned(),
            AppError::Unauthorized | AppError::InvalidCredentials => {
                "Authentication failed".to_owned()
            }
            AppError::Conflict(msg) => msg.clone(),
            AppError::Forbidden => "Forbidden".to_owned(),
            AppError::TenantRequired => "A current tenant is required".to_owned(),
            AppError::Internal(_) => "Internal server error".to_owned(),
        }
    }

    /// 排查需要的**原始细节** → 进日志。`None` = 无额外细节。
    /// 这是"原始错误一律落日志"的统一入口:BadRequest 落 rejection、Internal 落
    /// anyhow 的完整 source chain;将来 sqlx/io 错误经 `?` 进 Internal 也自动落这里。
    ///
    /// **落日志 ≠ 不进响应体**,两者由 [`Self::client_message`] 各自决定:BadRequest/Internal
    /// 的细节**只**进日志(响应体给通用措辞);Validation 的细节**两边都去** —— 它本就写给调用方,
    /// 同时运维也需要它。
    ///
    /// Validation 为什么必须落日志:`400`(serde 拒绝,缺字段)与 `422`(garde 拒绝,值不合法)
    /// 本是同一类事 —— "调用方发来的东西不对",只是被不同的层拦下。以前只有前者落日志,
    /// 于是**光看日志无法回溯任何 422**;而 `login` 这类公开端点的响应体在对方浏览器里,拿不到,
    /// 日志是唯一的窗口(且 422 早于 `emit_auth_event`,`auth_events` 审计表也兜不住它)。
    /// garde 的消息是规则级的(`identifier: length is lower than 1`),**只含字段名与规则、不含值**,
    /// 故不引入 PII;`identifier` 等入参也都已封顶,灌不爆日志。
    ///
    /// Conflict 刻意仍不落:它的消息是我们自己写的业务语句(如 "cannot remove your own admin
    /// access"),状态码 + 路径即可定位,落日志只是噪音。
    fn log_detail(&self) -> Option<String> {
        match self {
            AppError::BadRequest(detail) => Some(detail.clone()),
            AppError::Internal(err) => Some(format!("{err:?}")),
            AppError::Validation(msg) => Some(msg.clone()),
            AppError::NotFound
            | AppError::AccountNotFound
            | AppError::Unauthorized
            | AppError::InvalidCredentials
            | AppError::Conflict(_)
            | AppError::Forbidden
            | AppError::TenantRequired => None,
        }
    }
}

/// 错误机器码闭集(前端按它分支;闭集生成前端 union,见 closed-enums skill)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    Validation,
    BadRequest,
    /// 401:没登录 / 会话失效(token 无效、过期、已撤销)。前端见此码走刷新 / 会话过期流程。
    Unauthorized,
    /// 401:凭据错(登录密码错、改密旧密码错、注销密码确认错)。会话本身还有效,前端把错误交给调用方,
    /// 不刷新、不跳登录页。文案与 `unauthorized` 一样通用(防枚举)。
    InvalidCredentials,
    Conflict,
    Forbidden,
    /// 403:token 没有当前租户,却访问租户级接口(平台上下文 / 还没加入任何组织)。
    TenantRequired,
    /// 404:按用户名找不到账号(租户管理员按用户名加成员时)。与 `not_found` 分开,前端据此提示「账号不存在」。
    AccountNotFound,
    Internal,
    /// 仅 router 全局超时兜底路径产出(绕过 AppError)。
    Timeout,
    /// 仅 router 限流层产出(绕过 AppError)。
    RateLimited,
}

impl ErrorCode {
    /// 全部变体(wire round-trip 测试用)。镜像 `Perm::ALL`。
    ///
    /// **加变体必补这里,但漏了没人拦** —— `ALL` 是数组字面量,加变体不会让它编译失败;
    /// round-trip 测试遍历的正是 `ALL`,漏掉的变体只是从不被测(那条测试就是为了钉住
    /// `as_str()` 与 serde rename 不漂移,漏项恰好绕过它)。真正逼你回来的是 `as_str()`
    /// 的穷尽 match(编译不过),但它只让你**手写**一个 wire 串,不校验它等于 serde 的 rename。
    /// 后果:日志字段 `code`(as_str)与出参 `code`(serde)对新变体可能对不上。
    /// 要根治:声明宏单源展开 enum + `ALL` + `as_str`,让漏项不可表达。
    pub const ALL: [ErrorCode; 12] = [
        ErrorCode::NotFound,
        ErrorCode::Validation,
        ErrorCode::BadRequest,
        ErrorCode::Unauthorized,
        ErrorCode::InvalidCredentials,
        ErrorCode::Conflict,
        ErrorCode::Forbidden,
        ErrorCode::TenantRequired,
        ErrorCode::AccountNotFound,
        ErrorCode::Internal,
        ErrorCode::Timeout,
        ErrorCode::RateLimited,
    ];

    /// 日志字段用的 wire 串(== serde rename;`error_code_wire_matches` 测试钉死不漂移)。
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotFound => "not_found",
            ErrorCode::Validation => "validation",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::InvalidCredentials => "invalid_credentials",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::TenantRequired => "tenant_required",
            ErrorCode::AccountNotFound => "account_not_found",
            ErrorCode::Internal => "internal",
            ErrorCode::Timeout => "timeout",
            ErrorCode::RateLimited => "rate_limited",
        }
    }
}

/// 统一错误响应体。pub + ToSchema:让这个契约出现在 OpenAPI,前端 codegen 能看到错误形状。
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    /// 机器可读错误类别(闭集)
    pub code: ErrorCode,
    /// 给人看的安全消息 —— 不含 SQL/解析器/路径等任何内部原始措辞
    pub error: String,
}

/// HTTP 层的错误类型:包一层核心 [`AppError`],实现 axum 的 `IntoResponse`(孤儿规则不许直接给外部类型
/// `AppError` 实现外部 trait)。handler 返回 `Result<_, ApiError>`;service 返回的 `AppError` 经 `?` 自动转换。
#[derive(Debug)]
pub struct ApiError(pub AppError);

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}

// 常见上游错误直接 `?`(经 AppError 的同名 From 转换)。不写泛型 From —— 与标准库的自反 From 冲突。
impl From<garde::Report> for ApiError {
    fn from(e: garde::Report) -> Self {
        Self(e.into())
    }
}

impl From<idm::IdmError> for ApiError {
    fn from(e: idm::IdmError) -> Self {
        Self(e.into())
    }
}

impl From<content::ContentError> for ApiError {
    fn from(e: content::ContentError) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let ApiError(e) = self;
        let status = e.status_code();
        // 统一:任何带原始细节的错误都把原始内容写进日志(见 `log_detail`)。响应体里给什么由
        // `client_message` 单独决定 —— 多数变体只给通用措辞,Validation 例外(细节两边都给)。
        // 5xx 用 error、4xx 用 warn。日志在请求的 http span 内,自动带 request_id 可关联。
        if let Some(detail) = e.log_detail() {
            if status.is_server_error() {
                tracing::error!(code = e.code().as_str(), detail, "request failed");
            } else {
                tracing::warn!(code = e.code().as_str(), detail, "request rejected");
            }
        }
        let body = ErrorBody {
            code: e.code(),
            error: e.client_message(),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_detail_goes_to_log_never_to_response() {
        // BadRequest:库原始措辞(uuid 解析失败)进日志,响应只给安全文案
        let e = AppError::BadRequest("Cannot parse `id`: UUID parsing failed".to_owned());
        assert_eq!(e.client_message(), "Malformed request");
        assert!(!e.client_message().contains("UUID"));
        assert!(e.log_detail().unwrap().contains("UUID"));

        // Internal(将来 sqlx 错误同理):原始 SQL 进日志,响应只给通用文案
        let e = AppError::Internal(anyhow::anyhow!("relation \"widgets\" does not exist"));
        assert_eq!(e.client_message(), "Internal server error");
        assert!(!e.client_message().contains("widgets"));
        assert!(e.log_detail().unwrap().contains("widgets"));
        assert_eq!(e.code().as_str(), "internal");
    }

    #[test]
    fn client_facing_errors_keep_useful_message() {
        // NotFound 写给客户端、无额外细节可落
        assert_eq!(AppError::NotFound.client_message(), "Resource not found");
        assert!(AppError::NotFound.log_detail().is_none());

        let v = AppError::Validation("name: length is lower than 1".to_owned());
        assert!(v.client_message().contains("name"));
        assert_eq!(v.code().as_str(), "validation");
    }

    /// **422 的细节必须落日志**(而且照旧回传客户端 —— 两边都要)。
    ///
    /// 400(serde 拒绝,缺字段)与 422(garde 拒绝,值不合法)本是同一类事:"调用方发来的东西
    /// 不对",只是被不同的层拦下。以前只有 400 落日志,于是**光看日志无法回溯任何 422** ——
    /// 访问日志只有 `status=422`,原因全在响应体里;而 `login` 这类公开端点的响应体在对方浏览器
    /// 里拿不到,且 422 早于 `emit_auth_event`、`auth_events` 审计表也兜不住 → 三条观测路径全漏。
    #[test]
    fn validation_detail_reaches_both_log_and_client() {
        let v = AppError::Validation("identifier: length is lower than 1".to_owned());
        assert_eq!(
            v.log_detail().as_deref(),
            Some("identifier: length is lower than 1"),
            "422 的原因必须能从日志回溯(否则只剩一个光秃秃的 status=422)"
        );
        assert!(
            v.client_message().contains("identifier"),
            "同时照旧回传调用方 —— 这条细节本就是写给他的"
        );

        // 对照:400 一直落日志(同类事,口径必须一致)。
        assert!(AppError::BadRequest("missing field `password`".to_owned())
            .log_detail()
            .is_some());

        // 反面:Conflict 刻意不落 —— 消息是我们自己写的业务语句,状态码+路径即可定位。
        assert!(AppError::Conflict("already registered".to_owned())
            .log_detail()
            .is_none());
    }

    #[test]
    fn unauthorized_is_generic_to_prevent_enumeration() {
        // 401 文案必须通用:不暴露"是用户不存在还是密码错" —— 防账号枚举
        let e = AppError::Unauthorized;
        assert_eq!(e.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(e.code().as_str(), "unauthorized");
        assert_eq!(e.client_message(), "Authentication failed");
        assert!(e.log_detail().is_none());

        // Conflict:409,消息写给用户、可回传
        let c = AppError::Conflict("This email is already registered".to_owned());
        assert_eq!(c.status_code(), StatusCode::CONFLICT);
        assert_eq!(c.code().as_str(), "conflict");
        assert_eq!(c.client_message(), "This email is already registered");
    }

    #[test]
    fn account_not_found_is_404_with_its_own_code() {
        let e = AppError::AccountNotFound;
        assert_eq!(e.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(e.code().as_str(), "account_not_found");
        assert_eq!(e.client_message(), "Account not found");
        assert!(e.log_detail().is_none());
    }

    #[test]
    fn tenant_required_is_403_with_its_own_code() {
        let e = AppError::TenantRequired;
        assert_eq!(e.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(e.code().as_str(), "tenant_required");
        assert!(e.log_detail().is_none());
    }

    #[test]
    fn invalid_credentials_maps_to_401() {
        let e = AppError::from(idm::IdmError::InvalidCredentials(
            idm::CredentialFailure::BadPassword,
        ));
        assert!(matches!(e, AppError::InvalidCredentials));
        assert_eq!(e.status_code(), StatusCode::UNAUTHORIZED);
        // 机器码与会话失效的 `unauthorized` 分开(前端据此不把「密码输错」当「会话过期」);
        // 文案仍与 Unauthorized 一样通用,不区分「用户不存在 / 密码错」(防枚举)。
        assert_eq!(e.code().as_str(), "invalid_credentials");
        assert_eq!(e.client_message(), AppError::Unauthorized.client_message());
        assert!(e.log_detail().is_none());
    }

    #[test]
    fn error_code_wire_matches() {
        for c in ErrorCode::ALL {
            let wire = serde_json::to_value(c).unwrap();
            assert_eq!(
                wire.as_str(),
                Some(c.as_str()),
                "{c:?}: as_str ↔ serde rename"
            );
        }
    }
}
