//! widget 的 **HTTP 线格式**:请求/响应 JSON + OpenAPI schema,与领域模型(`model` / `widget_event` /
//! `ports::UserBrief`)互转。核心不知道这些类型的存在。
//!
//! **schema 名与 JSON 形状是对前端的契约**(前端按 OpenAPI 生成类型):类型名即 schema 名,改名 /
//! 改字段 = 破坏性变更。`WidgetEvent` 同时是事件总线(PG NOTIFY / NATS)的负载 —— SSE 帧与
//! 总线负载同一线格式,所以 `adapters::bus` 也用它序列化。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::features::widget::{model, ports, widget_event};
use crate::kernel::app_error::AppError;
use crate::kernel::tenant_id::TenantId;

/// 一个 widget(示例资源)+ 基础审计字段。时间是 RFC3339。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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

impl From<model::Widget> for Widget {
    fn from(widget: model::Widget) -> Self {
        Self {
            id: widget.id,
            name: widget.name,
            created_by: widget.created_by,
            created_at: widget.created_at,
            updated_by: widget.updated_by,
            updated_at: widget.updated_at,
        }
    }
}

impl From<Widget> for model::Widget {
    fn from(widget: Widget) -> Self {
        Self {
            id: widget.id,
            name: widget.name,
            created_by: widget.created_by,
            created_at: widget.created_at,
            updated_by: widget.updated_by,
            updated_at: widget.updated_at,
        }
    }
}

/// 创建 widget 的入参(name 1..=100 字符,由领域校验)。审计字段不入参。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWidget {
    pub name: String,
}

impl From<CreateWidget> for model::CreateWidget {
    fn from(input: CreateWidget) -> Self {
        Self { name: input.name }
    }
}

/// 更新 widget 的入参(当前只改名,全量替换)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWidget {
    pub name: String,
}

impl From<UpdateWidget> for model::UpdateWidget {
    fn from(input: UpdateWidget) -> Self {
        Self { name: input.name }
    }
}

/// 列表排序字段(白名单)。默认 `created_at`。
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidgetSortField {
    #[default]
    CreatedAt,
    Name,
}

impl From<WidgetSortField> for model::WidgetSortField {
    fn from(field: WidgetSortField) -> Self {
        match field {
            WidgetSortField::CreatedAt => Self::CreatedAt,
            WidgetSortField::Name => Self::Name,
        }
    }
}

/// 富化用的用户瘦快照(只含 widget 展示要的字段)。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserBrief {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
}

impl From<ports::UserBrief> for UserBrief {
    fn from(brief: ports::UserBrief) -> Self {
        Self {
            id: brief.id,
            username: brief.username,
            email: brief.email,
        }
    }
}

/// `Widget` + 富化的 created_by 用户(脏值/已删/无 → `null`)。
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

impl From<model::WidgetView> for WidgetView {
    fn from(view: model::WidgetView) -> Self {
        Self {
            id: view.id,
            name: view.name,
            created_by: view.created_by,
            created_at: view.created_at,
            updated_by: view.updated_by,
            updated_at: view.updated_at,
            created_by_user: view.created_by_user.map(UserBrief::from),
        }
    }
}

/// 计数响应(公开 stats / 我的计数 共用)。
#[derive(Debug, Serialize, ToSchema)]
pub struct WidgetStats {
    pub total: u64,
}

/// widget 变更事件(SSE 帧 data / 总线负载)。帧的 event name = `type` 标签(created/updated/deleted)。
/// `tenant_id` = 事件所属租户:总线跨实例扇出(PG NOTIFY / NATS)时靠它让订阅侧先按租户过滤;
/// SSE 帧里它总是订阅者自己的当前租户(别的租户的帧在 handler 里就跳过了)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WidgetEvent {
    Created {
        tenant_id: Uuid,
        widget: Widget,
    },
    Updated {
        tenant_id: Uuid,
        widget: Widget,
    },
    Deleted {
        tenant_id: Uuid,
        id: Uuid,
        created_by: Option<String>,
    },
}

impl From<widget_event::WidgetEvent> for WidgetEvent {
    fn from(event: widget_event::WidgetEvent) -> Self {
        match event {
            widget_event::WidgetEvent::Created { tenant_id, widget } => Self::Created {
                tenant_id: tenant_id.as_uuid(),
                widget: widget.into(),
            },
            widget_event::WidgetEvent::Updated { tenant_id, widget } => Self::Updated {
                tenant_id: tenant_id.as_uuid(),
                widget: widget.into(),
            },
            widget_event::WidgetEvent::Deleted {
                tenant_id,
                id,
                created_by,
            } => Self::Deleted {
                tenant_id: tenant_id.as_uuid(),
                id,
                created_by,
            },
        }
    }
}

/// 线格式 → 领域事件(总线订阅侧)。`tenant_id` 是 nil → 拒(nil 永远不是合法租户),订阅侧当坏 payload 跳过。
impl TryFrom<WidgetEvent> for widget_event::WidgetEvent {
    type Error = AppError;

    fn try_from(event: WidgetEvent) -> Result<Self, Self::Error> {
        Ok(match event {
            WidgetEvent::Created { tenant_id, widget } => Self::Created {
                tenant_id: TenantId::try_new(tenant_id)?,
                widget: widget.into(),
            },
            WidgetEvent::Updated { tenant_id, widget } => Self::Updated {
                tenant_id: TenantId::try_new(tenant_id)?,
                widget: widget.into(),
            },
            WidgetEvent::Deleted {
                tenant_id,
                id,
                created_by,
            } => Self::Deleted {
                tenant_id: TenantId::try_new(tenant_id)?,
                id,
                created_by,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 领域事件的 `name()`(SSE event name)必须等于线格式的 `type` 标签 —— 两处各写一份,在此钉住。
    #[test]
    fn event_name_matches_wire_tag() {
        let now = OffsetDateTime::now_utc();
        let widget = model::Widget {
            id: Uuid::now_v7(),
            name: "n".into(),
            created_by: None,
            created_at: now,
            updated_by: None,
            updated_at: now,
        };
        let tenant = TenantId::try_new(Uuid::now_v7()).unwrap();
        for event in [
            widget_event::WidgetEvent::Created {
                tenant_id: tenant,
                widget: widget.clone(),
            },
            widget_event::WidgetEvent::Updated {
                tenant_id: tenant,
                widget: widget.clone(),
            },
            widget_event::WidgetEvent::Deleted {
                tenant_id: tenant,
                id: widget.id,
                created_by: None,
            },
        ] {
            let wire = serde_json::to_value(WidgetEvent::from(event.clone())).unwrap();
            assert_eq!(wire["type"].as_str(), Some(event.name()));
            // 租户随线格式走(跨实例总线负载靠它让订阅侧先按租户过滤)
            assert_eq!(wire["tenant_id"], serde_json::json!(tenant.as_uuid()));
            // 往返:线格式 → 领域,无损(含租户)
            let parsed: WidgetEvent = serde_json::from_value(wire).unwrap();
            let back = widget_event::WidgetEvent::try_from(parsed).unwrap();
            assert_eq!(back, event);
        }
    }

    /// 负载里的 nil 租户 → 转领域事件失败(订阅侧当坏 payload 跳过,不当成任何租户的事件)。
    #[test]
    fn nil_tenant_on_the_wire_is_rejected() {
        let wire = WidgetEvent::Deleted {
            tenant_id: Uuid::nil(),
            id: Uuid::now_v7(),
            created_by: None,
        };
        assert!(widget_event::WidgetEvent::try_from(wire).is_err());
    }
}
