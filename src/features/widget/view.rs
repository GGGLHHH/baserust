//! widget 的**富化展示 DTO**。核心 `Widget`(FromRow,纯 app schema)+ 边缘叠加的 created_by 用户。
//! repo 层永不掺这些;富化只在 service 的组装步骤(`list_enriched`)发生 —— 这就是"边缘富化"。

use std::collections::HashMap;

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::port::UserBrief;
use super::types::Widget;

/// `Widget` + 富化的 created_by 用户(脏值/已删/无 → `None`)。
#[derive(Debug, Serialize, ToSchema)]
pub struct WidgetView {
    pub id: Uuid,
    pub name: String,
    /// 原审计主体标识(actor id 字符串),保留以便排错/审计。
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub updated_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// 富化:created_by 解析到的用户。脏值('system'/非 UUID)、已软删用户 → `None`。
    pub created_by_user: Option<UserBrief>,
}

/// 计数响应(公开 stats / 我的计数 共用)。
#[derive(Debug, Serialize, ToSchema)]
pub struct WidgetStats {
    pub total: u64,
}

impl WidgetView {
    /// 用一页富化结果(id→brief)把一个 `Widget` 拼成 `WidgetView`。
    pub fn enrich(w: Widget, dir: &HashMap<Uuid, UserBrief>) -> Self {
        let created_by_user = w
            .created_by
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok()) // 'system'/NULL/脏值 parse 失败即不富化
            .and_then(|id| dir.get(&id).cloned());
        Self {
            id: w.id,
            name: w.name,
            created_by: w.created_by,
            created_at: w.created_at,
            updated_by: w.updated_by,
            updated_at: w.updated_at,
            created_by_user,
        }
    }
}
