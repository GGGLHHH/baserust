//! Postgres 适配器共用的小件:核心类型 → sea-query 的映射。只给各模块 `adapters/postgres.rs` 这类适配器用,
//! 核心(`kernel` / 各模块的 model/service/端口)不碰 sea-query。

use crate::kernel::sort::SortOrder;

/// 核心排序方向 → sea-query 排序方向。
pub fn order(o: SortOrder) -> sea_query::Order {
    match o {
        SortOrder::Asc => sea_query::Order::Asc,
        SortOrder::Desc => sea_query::Order::Desc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_both_directions() {
        assert!(matches!(order(SortOrder::Asc), sea_query::Order::Asc));
        assert!(matches!(order(SortOrder::Desc), sea_query::Order::Desc));
        assert!(matches!(
            order(SortOrder::default()),
            sea_query::Order::Desc
        ));
    }
}
