//! idm 对外 DTO(契约数据形状)。出参 `Serialize + ToSchema`;入参 `Deserialize + ToSchema + Validate`。
//! 审计字段(created_by/at...)绝不入参,也不出现在对外响应。

use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// 注册请求(公开)。username 必填、唯一;email 可选。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct RegisterRequest {
    #[garde(length(min = 3, max = 32))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
    #[garde(length(min = 8))]
    pub password: String,
}

/// 登录请求(公开)。`identifier` = username 或 email,自动识别。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct LoginRequest {
    #[garde(length(min = 1))]
    pub identifier: String,
    #[garde(length(min = 1))]
    pub password: String,
}

/// 当前用户(me 响应)。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub roles: Vec<String>,
}

/// **全量更新**当前用户(PUT full update,非 PATCH)。username 必填;
/// email 给值=设置、给 null 或缺省=清空(请求体是资源的完整表示)。替换 email 会重置 email_verified。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateMeRequest {
    #[garde(length(min = 3, max = 32))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
}

/// 注销账户(需密码确认)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct DeleteMeRequest {
    #[garde(length(min = 1))]
    pub password: String,
}

/// 修改密码。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ChangePasswordRequest {
    #[garde(length(min = 1))]
    pub current_password: String,
    #[garde(length(min = 8))]
    pub new_password: String,
}
