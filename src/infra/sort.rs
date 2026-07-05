//! 共享排序方向。`sort_by` 字段枚举归各 feature(白名单,防注入);此处只放通用方向。
//! 排序是分页的**兄弟关注点**(切片归 `pagination`,排序归此),两者不混。

use serde::Deserialize;
use utoipa::ToSchema;

/// 排序方向。默认 `Desc`(最新/最大在前)。query 解析 `"asc"`/`"desc"`。
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

impl From<SortOrder> for sea_query::Order {
    fn from(o: SortOrder) -> Self {
        match o {
            SortOrder::Asc => sea_query::Order::Asc,
            SortOrder::Desc => sea_query::Order::Desc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_desc_and_maps() {
        assert!(matches!(SortOrder::default(), SortOrder::Desc));
        assert!(matches!(
            sea_query::Order::from(SortOrder::Asc),
            sea_query::Order::Asc
        ));
        let d: SortOrder = serde_json::from_str("\"asc\"").unwrap();
        assert!(matches!(d, SortOrder::Asc));
    }
}
