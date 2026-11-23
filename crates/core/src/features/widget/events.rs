//! widget 的**领域事件**。写成功后由 service 发布(fire-and-forget),SSE handler 订阅推给前端。
//! 总线端口见 `ports::EventBus`;内存 / PG / NATS 实现在 `adapters`。

use uuid::Uuid;

use super::model::Widget;

/// widget 变更事件(领域事件)。线格式(SSE 帧 / 总线负载的 JSON,`type` 标签)在 `adapters::http::dto`。
///
/// **每个变体都带得出 owner**([`WidgetEvent::owner`])—— SSE handler 要按 `Access` 逐帧过滤,
/// 没 owner 的帧无法判定:放行=泄露、丢弃=owner 收不到自己的删除。`Deleted` 因此单带 `created_by`
/// (删除后行已软删,订阅侧无从回查)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WidgetEvent {
    Created {
        widget: Widget,
    },
    Updated {
        widget: Widget,
    },
    Deleted {
        id: Uuid,
        created_by: Option<String>,
    },
}

impl WidgetEvent {
    /// 事件名(SSE 帧的 event name;与线格式的 `type` 标签一致,`adapters::http::dto` 有测试钉住)。
    pub fn name(&self) -> &'static str {
        match self {
            WidgetEvent::Created { .. } => "created",
            WidgetEvent::Updated { .. } => "updated",
            WidgetEvent::Deleted { .. } => "deleted",
        }
    }

    /// 该事件所指 widget 的 `created_by`(行级 ownership 判定用)。
    /// 喂 [`Access::allows_created_by`](crate::kernel::authz::Access::allows_created_by):
    /// `None` / 非 UUID 脏值在 `Own` 下一律不可见 —— 与 list 的 `owner_filter`(`created_by = me`)同口径。
    pub fn owner(&self) -> Option<&str> {
        match self {
            WidgetEvent::Created { widget } | WidgetEvent::Updated { widget } => {
                widget.created_by.as_deref()
            }
            WidgetEvent::Deleted { created_by, .. } => created_by.as_deref(),
        }
    }
}
