//! 排序方向的 **HTTP 适配**:query 里的 `"asc"`/`"desc"` + OpenAPI schema `SortOrder`。
//! 核心侧的方向是 `kernel::sort_order::SortOrder`(纯枚举),两者一一对应。

use serde::Deserialize;
use utoipa::ToSchema;

use crate::kernel::sort_order::SortOrder as CoreSortOrder;

/// 排序方向(线格式)。默认 `Desc`(最新/最大在前)。
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

impl From<SortOrder> for CoreSortOrder {
    fn from(order: SortOrder) -> Self {
        match order {
            SortOrder::Asc => CoreSortOrder::Asc,
            SortOrder::Desc => CoreSortOrder::Desc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_desc_and_maps() {
        assert!(matches!(SortOrder::default(), SortOrder::Desc));
        assert_eq!(CoreSortOrder::from(SortOrder::Asc), CoreSortOrder::Asc);
        let parsed: SortOrder = serde_json::from_str("\"asc\"").unwrap();
        assert!(matches!(parsed, SortOrder::Asc));
    }
}
