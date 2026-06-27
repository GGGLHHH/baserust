use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// 一个 widget(示例资源)。范式:出参 DTO derive `Serialize` + `ToSchema`;
/// `FromRow` 让它能直接被 sqlx `query_as` 映射。
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct Widget {
    pub id: Uuid,
    pub name: String,
}

/// 创建 widget 的入参。范式:
/// - `Deserialize`(解析 body)+ `ToSchema`(进 OpenAPI)+ `Validate`(garde 校验)。
/// - 注意「双注解」:garde 的 `length` 约束 utoipa 看不到,OpenAPI schema 不会自动带
///   minLength/maxLength。要让规范也体现约束,得另加 `#[schema(min_length = 1)]` 手动同步
///   (脚手架先不写,等真要发布契约约束时再加)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateWidget {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}
