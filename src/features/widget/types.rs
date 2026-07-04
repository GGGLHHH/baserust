use garde::Validate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// 一个 widget(示例资源)+ **基础审计字段**(供后续业务 DTO 照抄)。
/// 范式:出参 DTO derive `Serialize` + `ToSchema`;`FromRow` 让 sqlx/sea-query 直接映射。
/// `deleted_at` **不进 DTO**:可见行恒为存活(NULL),暴露无意义且会误导客户端。
/// 时间用 `OffsetDateTime`(timestamptz),RFC3339 序列化。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct Widget {
    pub id: Uuid,
    pub name: String,
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub updated_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// 创建 widget 的入参。审计字段绝不入参(由 `AuditContext` 提供 created_by/updated_by)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateWidget {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}

/// 更新 widget 的入参(当前只改名)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateWidget {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}
