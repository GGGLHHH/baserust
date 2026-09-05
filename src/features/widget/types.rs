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

/// 列表排序字段(**白名单** —— 只暴露可排的列,防注入)。默认 `created_at`(配 `SortOrder::Desc` = 最新在前)。
/// 范式:排序方向共享(`infra::sort::SortOrder`),可排字段各 feature 自己圈定。
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidgetSortField {
    #[default]
    CreatedAt,
    Name,
}

impl WidgetSortField {
    /// 映射到 sea-query 列标识符。
    pub(crate) fn column(&self) -> super::repo::Widgets {
        match self {
            Self::CreatedAt => super::repo::Widgets::CreatedAt,
            Self::Name => super::repo::Widgets::Name,
        }
    }

    /// 能否作 cursor keyset 键。**准入三条,缺一不可**:
    /// 1. 列 `NOT NULL` —— 可空键的 keyset 谓词要跨 NULL 边界(三分支),内存实现极易与 PG 漂移;
    /// 2. 有 `(key, id)` 复合索引 —— 否则 keyset 深翻退化成全表排序,白付复杂度;
    /// 3. 文本键的 PG collation 与内存 `str Ord` 一致(见 `postgres::sort_expr` 的 `COLLATE "C"`)
    ///    —— offset 下不一致只是顺序难看,keyset 下**直接漏行**。
    ///
    /// **放开一个键 = 改这里 + 加索引 + 加一条 conformance 用例。**
    /// 不满足就留 `false`:该键只走 offset,handler 返回 422 而非静默按别的键排。
    pub(crate) fn keyset_capable(&self) -> bool {
        match self {
            // v7 id 代理创建序,复用主键索引,无需额外索引也无需读锚点行。
            Self::CreatedAt => true,
            // name not null + widgets_alive_name_id_idx + COLLATE "C"。
            Self::Name => true,
        }
    }
}
