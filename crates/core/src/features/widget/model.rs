//! widget 的**领域模型**:实体、命令、读模型、可排序字段。纯 Rust —— 不知道 HTTP、数据库、
//! OpenAPI 的存在。请求/响应的 JSON 形状在 `adapters::http::dto`,数据库行在 `adapters::postgres`,
//! 它们各自与这里的类型互转。

use std::collections::HashMap;

use garde::Validate;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ports::UserBrief;

/// 一个 widget(示例资源)+ **基础审计字段**(供后续业务模型照抄)。
/// 只含存活行看得到的字段:`deleted_at` 是持久化细节(软删除),不进领域模型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Widget {
    pub id: Uuid,
    pub name: String,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_by: Option<String>,
    pub updated_at: OffsetDateTime,
}

/// 创建命令。审计字段绝不入参(由 `AuditContext` 提供 created_by/updated_by)。
/// 校验规则是**领域不变量**,写在这里、由 service 执行 —— 不管调用方是 HTTP、seed 还是测试都一样。
#[derive(Debug, Clone, Validate)]
pub struct CreateWidget {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}

/// 更新命令(当前只改名,全量替换语义)。
#[derive(Debug, Clone, Validate)]
pub struct UpdateWidget {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}

/// 列表排序字段(**白名单** —— 只开放可排的字段)。默认 `CreatedAt`(配 `SortOrder::Desc` = 最新在前)。
/// 排序方向共享(`kernel::sort_order::SortOrder`),可排字段各 feature 自己圈定;到列名的映射归仓储适配器。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WidgetSortField {
    #[default]
    CreatedAt,
    Name,
}

impl WidgetSortField {
    /// 能否作 cursor keyset 键。**准入三条,缺一不可**:
    /// 1. 列 `NOT NULL` —— 可空键的 keyset 谓词要跨 NULL 边界(三分支),内存实现极易与 PG 漂移;
    /// 2. 有 `(key, id)` 复合索引 —— 否则 keyset 深翻退化成全表排序,白付复杂度;
    /// 3. 文本键的 PG collation 与内存 `str Ord` 一致(见 `adapters::postgres::sort_expr` 的 `COLLATE "C"`)
    ///    —— offset 下不一致只是顺序难看,keyset 下**直接漏行**。
    ///
    /// **放开一个键 = 改这里 + 加索引 + 加一条 conformance 用例。**
    /// 不满足就留 `false`:该键只走 offset,handler 返回 422 而非静默按别的键排。
    #[must_use]
    pub fn keyset_capable(&self) -> bool {
        match self {
            // v7 id 代理创建序,复用主键索引,无需额外索引也无需读锚点行。
            Self::CreatedAt => true,
            // name not null + widgets_alive_name_id_idx + COLLATE "C"。
            Self::Name => true,
        }
    }
}

/// widget 的**富化读模型**:核心 `Widget` + 边缘叠加的 created_by 用户。
/// 仓储永不掺这些;富化只在 service 的组装步骤(`list_enriched`)发生 —— 这就是"边缘富化"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidgetView {
    pub id: Uuid,
    pub name: String,
    /// 原审计主体标识(actor id 字符串),保留以便排错/审计。
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_by: Option<String>,
    pub updated_at: OffsetDateTime,
    /// 富化:created_by 解析到的用户。脏值('system'/非 UUID)、已软删用户 → `None`。
    pub created_by_user: Option<UserBrief>,
}

impl WidgetView {
    /// 用一页富化结果(id→brief)把一个 `Widget` 拼成 `WidgetView`。
    #[must_use]
    pub fn new_with_directory(widget: Widget, directory: &HashMap<Uuid, UserBrief>) -> Self {
        let created_by_user = widget
            .created_by
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok()) // 'system'/NULL/脏值 parse 失败即不富化
            .and_then(|id| directory.get(&id).cloned());
        Self {
            id: widget.id,
            name: widget.name,
            created_by: widget.created_by,
            created_at: widget.created_at,
            updated_by: widget.updated_by,
            updated_at: widget.updated_at,
            created_by_user,
        }
    }
}
