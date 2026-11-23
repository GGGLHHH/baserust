//! 分页的 **HTTP 适配**:query 参数解析(`PageQuery` → 核心 `PageParams`)、opaque cursor 编解码、
//! 统一响应 JSON 形状(`Page<T>` / `PageInfo`)。核心侧的参数与结果见 `kernel::pagination`。
//!
//! 为什么双模式:任意跳页需 OFFSET、深翻 O(log n) 需 keyset,一条 SQL 不可兼得 ——
//! 所以两套并存,按参数选。默认 offset(后台管理跳页),带 cursor 即切高性能模式。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::kernel::error::AppError;
use crate::kernel::pagination::{self as core, PageParams};

const DEFAULT_SIZE: u64 = 20;
const MAX_SIZE: u64 = 100;

/// 边界 query 参数(进 axum `Query` 提取 + OpenAPI)。扁平 `Option` 比 enum 更适合 query string。
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// 提供 ⇒ offset 模式(可跳页),1-based。
    pub page: Option<u64>,
    /// 提供 ⇒ cursor 模式;opaque token,原样回传、勿解析。空值 `cursor=` = 首页。
    /// serde_html_form 基座(见 infra/http/extract.rs)会把空值 Option 解成 None,丢掉
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

impl PageQuery {
    /// 互斥校验 + clamp + 默认,一处搞定,产出核心的 [`PageParams`]。不走 garde(对 `Option` 的
    /// range 有版本差异),size 越界用 clamp(更友好)、page/cursor 同传则 reject(语义错误)。
    pub fn resolve(self) -> Result<PageParams, AppError> {
        let size = self.size.unwrap_or(DEFAULT_SIZE).clamp(1, MAX_SIZE);
        match (self.page, self.cursor) {
            // page + cursor(含空值)互斥:空 cursor= 已是"cursor 模式首页"的表达,
            // 再带 page 就是语义冲突 —— 静默吞掉任何一个都会让分页 UI 无声卡死。
            (Some(_), Some(_)) => Err(AppError::Validation(
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
            // 无 cursor → offset(可跳页),默认第 1 页。上限夹到 i64::MAX/MAX_SIZE:
            // (page-1)*size 既不打爆 u64 乘法,也不超 PG bigint 的 OFFSET 取值域。
            (page, None) => Ok(PageParams::Offset {
                page: page.unwrap_or(1).clamp(1, i64::MAX as u64 / MAX_SIZE),
                size,
                with_total: self.with_total.unwrap_or(true),
            }),
        }
    }
}

/// 统一分页响应。utoipa 5 把 `Page<WidgetView>` 渲染成 schema `Page_WidgetView`(泛型自动命名),
/// path 自动收集,无需 `#[aliases]`(v5 已移除)。由核心 `Page<T>` 经 [`Page::from_core`] 转来。
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
    /// 核心分页结果 → 响应 DTO:item 逐个转成 DTO,cursor 锚点编成 opaque token。
    pub fn from_core<U>(page: core::Page<U>, item: impl FnMut(U) -> T) -> Self {
        let page_info = match page.page_info {
            core::PageInfo::Offset {
                page,
                size,
                total,
                total_pages,
            } => PageInfo::Offset {
                page,
                size,
                total,
                total_pages,
            },
            core::PageInfo::Cursor {
                limit,
                next_after,
                has_more,
            } => PageInfo::Cursor {
                limit,
                next_cursor: next_after.map(encode_cursor),
                has_more,
            },
        };
        Page {
            items: page.items.into_iter().map(item).collect(),
            page_info,
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
    use crate::kernel::pagination::PageParams;

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
        // 空 cursor= 也互斥:不能静默吞 page 进 cursor 首页。
        let q = PageQuery {
            page: Some(2),
            cursor: Some(String::new()),
            size: None,
            with_total: None,
        };
        assert!(matches!(q.resolve(), Err(AppError::Validation(_))));
        // 单独的空 cursor= = keyset 首页。
        let q = PageQuery {
            page: None,
            cursor: Some(String::new()),
            size: None,
            with_total: None,
        };
        assert!(matches!(
            q.resolve(),
            Ok(PageParams::Cursor { after: None, .. })
        ));
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
