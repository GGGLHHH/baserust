//! 时间区间 `[from, to)`(统计 / 监控查询共用)。

use time::OffsetDateTime;

/// 左闭右开的时间区间 `[from, to)`。两个时刻按名字区分,不靠参数位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    /// 起点(含)。
    pub from: OffsetDateTime,
    /// 终点(不含)。
    pub to: OffsetDateTime,
}

/// 请求里带来的时间区间,两头都可以不给(由用例决定缺省值)。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestedTimeRange {
    /// 起点;`None` = 用例的缺省起点。
    pub from: Option<OffsetDateTime>,
    /// 终点;`None` = 用例的缺省终点(通常是现在)。
    pub to: Option<OffsetDateTime>,
}
