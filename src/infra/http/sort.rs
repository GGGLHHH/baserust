//! 排序方向的 **HTTP 适配**:query 里的 `"asc"`/`"desc"` + OpenAPI schema `SortOrder`。
//! 核心侧的方向是 `kernel::sort::SortOrder`(纯枚举),两者一一对应。

use serde::Deserialize;
use utoipa::ToSchema;

use crate::kernel::sort::SortOrder as Core;

/// 排序方向(线格式)。默认 `Desc`(最新/最大在前)。
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

impl From<SortOrder> for Core {
    fn from(o: SortOrder) -> Self {
        match o {
            SortOrder::Asc => Core::Asc,
            SortOrder::Desc => Core::Desc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_desc_and_maps() {
        assert!(matches!(SortOrder::default(), SortOrder::Desc));
        assert_eq!(Core::from(SortOrder::Asc), Core::Asc);
        let d: SortOrder = serde_json::from_str("\"asc\"").unwrap();
        assert!(matches!(d, SortOrder::Asc));
    }
}
