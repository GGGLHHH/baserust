//! 共享排序方向。`sort_by` 字段枚举归各 feature(白名单,防注入);此处只放通用方向。
//! 排序是分页的**兄弟关注点**(切片归 `pagination`,排序归此),两者不混。
//! query 解析(`"asc"`/`"desc"`)归 `infra::http::sort`,到 sea-query 的映射归 `infra::pg`。

/// 排序方向。默认 `Desc`(最新/最大在前)。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}
