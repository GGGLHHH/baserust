//! widget 的**领域事件**。写成功后由 service 发布(fire-and-forget),SSE handler 订阅推给前端。
//! 总线端口见 `ports::EventBus`;内存 / PG / NATS 实现在 `adapters`。

use uuid::Uuid;

use super::model::Widget;
use crate::kernel::tenant_id::TenantId;

/// widget 变更事件(领域事件)。线格式(SSE 帧 / 总线负载的 JSON,`type` 标签)在 `adapters::http::dto`。
///
/// **每个变体都带租户**([`WidgetEvent::tenant_id`]):总线是全实例广播(内存 / PG NOTIFY / NATS 都不分租户频道),
/// SSE handler 逐帧**先比租户**、再比 owner —— 不带租户的帧没法判定归属,只能丢。租户随总线负载一起序列化
/// (线格式 `adapters::http::dto::WidgetEvent` 的 `tenant_id`),跨实例也不丢。
///
/// **每个变体都带得出 owner**([`WidgetEvent::owner`])—— SSE handler 要按 `Access` 逐帧过滤,
/// 没 owner 的帧无法判定:放行=泄露、丢弃=owner 收不到自己的删除。`Deleted` 因此单带 `created_by`
/// (删除后行已软删,订阅侧无从回查)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WidgetEvent {
    Created {
        tenant_id: TenantId,
        widget: Widget,
    },
    Updated {
        tenant_id: TenantId,
        widget: Widget,
    },
    Deleted {
        tenant_id: TenantId,
        id: Uuid,
        created_by: Option<String>,
    },
}

impl WidgetEvent {
    /// 事件名(SSE 帧的 event name;与线格式的 `type` 标签一致,`adapters::http::dto` 有测试钉住)。
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            WidgetEvent::Created { .. } => "created",
            WidgetEvent::Updated { .. } => "updated",
            WidgetEvent::Deleted { .. } => "deleted",
        }
    }

    /// 事件所属租户(SSE 逐帧过滤的第一道:不是当前租户的帧直接跳过)。
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        match self {
            WidgetEvent::Created { tenant_id, .. }
            | WidgetEvent::Updated { tenant_id, .. }
            | WidgetEvent::Deleted { tenant_id, .. } => *tenant_id,
        }
    }

    /// 该事件所指 widget 的 `created_by`(行级 ownership 判定用)。
    /// 喂 [`Access::allows_created_by`](crate::kernel::authorization::Access::allows_created_by):
    /// `None` / 非 UUID 脏值在 `Own` 下一律不可见 —— 与 list 的 `owner_filter`(`created_by = me`)同口径。
    #[must_use]
    pub fn owner(&self) -> Option<&str> {
        match self {
            WidgetEvent::Created { widget, .. } | WidgetEvent::Updated { widget, .. } => {
                widget.created_by.as_deref()
            }
            WidgetEvent::Deleted { created_by, .. } => created_by.as_deref(),
        }
    }
}
