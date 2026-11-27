//! 分页的**领域侧**:参数(`PageParams`)与结果(`Page<T>`)。跨业务模块共享。
//!
//! offset(可跳页 + total)/ cursor(keyset 高性能 + 并发稳定)双模式。cursor 排序键 = **uuid v7 id**
//! (v7 高位含毫秒时间、单调递增、构造即唯一)。核心里 cursor 就是那个 id(`after` / `next_after`);
//! 编成 opaque 字符串、从 query 解析、JSON 形状 —— 都是线格式,归 `infra::http::pagination`。

use uuid::Uuid;

/// 分页参数(service/repo `match`)。HTTP 边界由 `infra::http::pagination::PageQuery::resolve` 产出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageParams {
    Offset {
        page: u64,
        size: u64,
        with_total: bool,
    },
    Cursor {
        /// 上一页最后一行的 id;首页为 None。
        after: Option<Uuid>,
        limit: u64,
    },
}

/// 一页结果 + 分页元信息。
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page_info: PageInfo,
}

/// 分页元信息:offset 给 total/total_pages,cursor 给下一页锚点 `next_after`(无下一页为 None)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageInfo {
    Offset {
        page: u64,
        size: u64,
        total: Option<u64>,
        total_pages: Option<u64>,
    },
    Cursor {
        limit: u64,
        /// 下一页的 `after`(= 本页最后一行的 id);`None` = 没有下一页。
        next_after: Option<Uuid>,
        has_more: bool,
    },
}

/// offset 模式下这一页的位置:第几页(从 1 起)、每页几条。两个 `u64` 按名字区分,不靠参数位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetPosition {
    pub page: u64,
    pub size: u64,
}

impl<T> Page<T> {
    /// offset 结果组装。total 为 `None` 表示未计算(with_total=false)。
    #[must_use]
    pub fn new_with_offset(items: Vec<T>, position: OffsetPosition, total: Option<u64>) -> Self {
        let OffsetPosition { page, size } = position;
        let total_pages = total.map(|t| t.div_ceil(size.max(1)));
        Page {
            items,
            page_info: PageInfo::Offset {
                page,
                size,
                total,
                total_pages,
            },
        }
    }

    /// cursor 结果组装:多取的一行(limit+1)由调用方先 trim、传入下一页锚点。
    #[must_use]
    pub fn new_with_cursor(items: Vec<T>, limit: u64, next_after: Option<Uuid>) -> Self {
        Page {
            items,
            page_info: PageInfo::Cursor {
                limit,
                has_more: next_after.is_some(),
                next_after,
            },
        }
    }

    /// 把每个 item 映射成另一类型,`page_info` 原样保留(跨模块**边缘富化** / 转 DTO 用)。
    pub fn map_items<U>(self, transform: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(transform).collect(),
            page_info: self.page_info,
        }
    }
}
