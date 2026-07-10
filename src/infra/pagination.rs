//! 分页范式:**offset**(可跳页 + total)/ **cursor**(keyset 高性能 + 并发稳定)双模式,
//! 统一 `Page<T>` 响应。跨业务模块共享。cursor 排序键 = **uuid v7 id 单列**
//! (v7 高位含毫秒时间、单调递增、构造即唯一 → 单列严格全序,复用主键、无需复合键/tiebreaker)。
//!
//! 为什么双模式:任意跳页需 OFFSET、深翻 O(log n) 需 keyset,一条 SQL 不可兼得 ——
//! 所以两套并存,按参数选。默认 offset(后台管理跳页),带 cursor 即切高性能模式。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::infra::error::AppError;

const DEFAULT_SIZE: u64 = 20;
const MAX_SIZE: u64 = 100;

/// 边界 query 参数(进 axum `Query` 提取 + OpenAPI)。扁平 `Option` 比 enum 更适合 query string。
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// 提供 ⇒ offset 模式(可跳页),1-based。
    pub page: Option<u64>,
    /// 提供 ⇒ cursor 模式;opaque token,原样回传、勿解析。空值 `cursor=` = 首页。
    /// serde_html_form 基座(见 infra/extract.rs)会把空值 Option 解成 None,丢掉
    /// "cursor 模式首页"的表达 —— 自定义 deserializer 保住 `Some("")`。
    #[serde(default, deserialize_with = "de_keep_empty")]
    pub cursor: Option<String>,
    /// 每页条数,两模式共用;越界自动 clamp 到 [1,100]。
    pub size: Option<u64>,
    /// 仅 offset 有意义:是否计算 total(默认 true)。
    pub with_total: Option<bool>,
}

/// 键存在即 `Some`(含空值),键缺席走 `#[serde(default)]` → `None`。
fn de_keep_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    serde::Deserialize::deserialize(d).map(Some)
}

/// 域内分页参数(service/repo `match`)。由 `PageQuery::resolve()` 产出。
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

impl PageQuery {
    /// 互斥校验 + clamp + 默认,一处搞定。不走 garde(对 `Option` 的 range 有版本差异),
    /// size 越界用 clamp(更友好)、page/cursor 同传则 reject(语义错误)。
    pub fn resolve(self) -> Result<PageParams, AppError> {
        let size = self.size.unwrap_or(DEFAULT_SIZE).clamp(1, MAX_SIZE);
        match (self.page, self.cursor) {
            // page + 非空 cursor 互斥(语义冲突)
            (Some(_), Some(c)) if !c.is_empty() => Err(AppError::Validation(
                "page and cursor are mutually exclusive".into(),
            )),
            // 有 cursor 参数即 cursor 模式:空字符串 = 首页(after=None),非空 = 解码锚点。
            // (空 cursor 让"cursor 模式第一页"可表达,否则首页无 cursor 就只能退回 offset)
            (_, Some(c)) => Ok(PageParams::Cursor {
                after: if c.is_empty() {
                    None
                } else {
                    Some(decode_cursor(&c)?)
                },
                limit: size,
            }),
            // 无 cursor → offset(可跳页),默认第 1 页
            (page, None) => Ok(PageParams::Offset {
                page: page.unwrap_or(1).max(1),
                size,
                with_total: self.with_total.unwrap_or(true),
            }),
        }
    }
}

/// 统一分页响应。utoipa 5 把 `Page<Widget>` 渲染成 schema `Page_Widget`(泛型自动命名),
/// path 自动收集,无需 `#[aliases]`(v5 已移除)。
#[derive(Debug, Serialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page_info: PageInfo,
}

/// 分页元信息:offset 给 total/total_pages,cursor 给 next_cursor/has_more。
/// 内部标签 `mode` 区分(类型诚实:cursor 模式不可能混入 total);utoipa 生成带 mode 判别的 oneOf。
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PageInfo {
    Offset {
        page: u64,
        size: u64,
        total: Option<u64>,
        total_pages: Option<u64>,
    },
    Cursor {
        limit: u64,
        next_cursor: Option<String>,
        has_more: bool,
    },
}

impl<T> Page<T> {
    /// offset 结果组装。total 为 `None` 表示未计算(with_total=false)。
    pub fn offset(items: Vec<T>, page: u64, size: u64, total: Option<u64>) -> Self {
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

    /// cursor 结果组装:多取的一行(limit+1)由调用方先 trim、传入 next_cursor。
    pub fn cursor(items: Vec<T>, limit: u64, next_cursor: Option<String>) -> Self {
        Page {
            items,
            page_info: PageInfo::Cursor {
                limit,
                has_more: next_cursor.is_some(),
                next_cursor,
            },
        }
    }

    /// 把每个 item 映射成另一类型,`page_info` 原样保留。跨模块**边缘富化**用:
    /// `Page<Widget>` → `Page<WidgetView>`(分页元信息不变,只换 item 形状)。
    pub fn map_items<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            page_info: self.page_info,
        }
    }
}

/// cursor = 上一页最后一行的 v7 id,编成 opaque base64url(16 字节)。
/// v7 单列即严格全序,keyset 只需 `id < cursor`。opaque:客户端不能解析 → 日后换键不破契约。
pub fn encode_cursor(id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(id.as_bytes())
}

/// 解码 cursor;失败一律 → `BadRequest`(原始细节进日志、不泄露),绝不 panic/500。
pub fn decode_cursor(s: &str) -> Result<Uuid, AppError> {
    let raw = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AppError::BadRequest("Invalid cursor".into()))?;
    Uuid::from_slice(&raw).map_err(|_| AppError::BadRequest("Invalid cursor".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_roundtrips() {
        let id = Uuid::now_v7();
        assert_eq!(decode_cursor(&encode_cursor(id)).unwrap(), id);
    }

    #[test]
    fn bad_cursor_is_bad_request() {
        assert!(matches!(
            decode_cursor("!!!not-base64!!!"),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn page_and_cursor_mutually_exclusive() {
        let q = PageQuery {
            page: Some(1),
            cursor: Some("x".into()),
            size: None,
            with_total: None,
        };
        assert!(matches!(q.resolve(), Err(AppError::Validation(_))));
    }

    #[test]
    fn size_clamps_to_max() {
        let q = PageQuery {
            page: Some(1),
            cursor: None,
            size: Some(99999),
            with_total: None,
        };
        match q.resolve().unwrap() {
            PageParams::Offset { size, .. } => assert_eq!(size, MAX_SIZE),
            _ => panic!("应是 offset 模式"),
        }
    }
}
