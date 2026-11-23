//! 核心错误类型。HTTP 映射(状态码 / 机器码 / 安全消息 / 落日志)见 `infra::http::error`。

/// 应用统一错误类型(核心侧)。范式:
/// - 变体表达**业务语义**(不存在 / 校验失败 / 冲突 / 无权限 …),不含任何 HTTP 概念。
/// - 业务/仓储层返回它;handler 用 `?` 传播。变体 → HTTP 状态码 / 机器码 / 响应体的映射
///   归 HTTP 适配层(`infra::http::error`),核心不知道自己会被翻成 404 还是别的。
///
/// **统一错误契约(关键)**:任何携带底层原始错误的变体,原始细节只进**日志**
/// (`log_detail`),响应体只给刻意写的**安全消息**(`client_message`)。不管来源是
/// uuid 解析、sqlx、还是 io,都绝不会把原始措辞漏给客户端 —— 加新错误来源时只要走
/// 这套契约,就天然不泄露。加错误种类 = 加变体 + 在下面四个 match 各补一行。
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("resource not found")]
    NotFound,

    /// 业务校验失败(garde)。消息是为用户写的、安全的,可回传给客户端。
    #[error("invalid request: {0}")]
    Validation(String),

    /// 请求格式错误(路径参数类型不匹配、body 非法 JSON 等)→ 400。
    /// 内含的字符串是**原始提取错误**(库措辞),只进日志、不进响应体。
    #[error("malformed request")]
    BadRequest(String),

    /// 未认证 / 凭据无效(登录失败、token 无效或过期、改密旧密码错)→ 401。
    /// `client_message` 刻意通用,**绝不区分"用户不存在"与"密码错误"**(防账号枚举)。
    #[error("authentication failed")]
    Unauthorized,

    /// 资源冲突(注册时 email 已占用)→ 409。消息写给用户、可回传(不含内部措辞)。
    #[error("conflict: {0}")]
    Conflict(String),

    /// 已认证但**无权限**(RBAC/scope gate 不通过)→ 403。与 401 区分:401=没认证/token 无效,
    /// 403=认证了但权限不够。文案刻意通用,不暴露"缺哪个权限"。
    #[error("forbidden")]
    Forbidden,

    /// 兜底:任何 anyhow 错误(DB、IO、依赖)→ 500。原始 source chain 只进日志。
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// garde 校验失败 → `Validation`,让 service 能用 `?` 直接传播。
impl From<garde::Report> for AppError {
    fn from(report: garde::Report) -> Self {
        AppError::Validation(report.to_string())
    }
}

/// idm 库的领域错误 `IdmError` 接进 app 错误体系(领域语义对领域语义;HTTP 形状再由适配层决定)。
/// idm 是零 HTTP 的纯库,只暴露 4 个领域变体;校验(422)/坏请求(400)是 app 自己的边界产物
/// (garde / Json 提取器 → `AppError::Validation`/`BadRequest`),不经此映射。
impl From<idm::IdmError> for AppError {
    fn from(e: idm::IdmError) -> Self {
        match e {
            idm::IdmError::NotFound => AppError::NotFound,
            idm::IdmError::Unauthorized => AppError::Unauthorized,
            // 失败原因只供审计(handler 发事件时读),HTTP 仍统一 401,防枚举不变。
            idm::IdmError::InvalidCredentials(_) => AppError::Unauthorized,
            idm::IdmError::Conflict(m) => AppError::Conflict(m),
            idm::IdmError::Internal(e) => AppError::Internal(e),
        }
    }
}

/// content 库的领域错误 `ContentError` 接进 app 错误体系(领域语义对领域语义;HTTP 形状再由适配层决定)。
/// content 是零 HTTP 的纯库,只暴露领域语义;映射对齐其文档分组(见 content::error):
/// not-found→404;not-ready / invalid-state / conflict→409(状态/冲突类);
/// invalid-status / storage / internal→500(invalid-status = DB 存了无法解析的状态串,是数据完整性
/// 故障而非客户端可修的校验错;原始值/source 含 key/backend/脏值,只进日志、绝不进响应体)。
/// 校验(422)/坏请求(400)是 app 边界产物(garde / 提取器 → Validation/BadRequest),不经此映射。
impl From<content::ContentError> for AppError {
    fn from(e: content::ContentError) -> Self {
        use content::ContentError as CE;
        match e {
            CE::NotFound => AppError::NotFound,
            CE::NotReady(m) | CE::InvalidState(m) | CE::Conflict(m) => AppError::Conflict(m),
            // DB 边界解析失败(脏状态串):内部数据完整性故障 → 500,原始脏值只进日志不回传。
            CE::InvalidStatus(m) => {
                AppError::Internal(anyhow::anyhow!("content status 解析失败(DB 脏值): {m}"))
            }
            CE::Storage(e) | CE::Internal(e) => AppError::Internal(e),
        }
    }
}
