//! 手写 OpenAPI schema 的小工具。核心里的闭集枚举(`Permission` / `RoleName` / 审计闭集 …)只派生 serde,
//! 不派生 `utoipa::ToSchema`(核心不依赖 OpenAPI);它们的 schema 由 HTTP 适配层用这里手写实现。

use serde::Serialize;
use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};
use utoipa::openapi::RefOr;

/// 闭集枚举的 OpenAPI schema:`type: string` + 每个变体的 wire 串(取自 serde,与序列化同源不漂移)。
///
/// # Panics
///
/// `all` 里有值不序列化成 JSON 字符串时 panic —— 闭集枚举都是单元变体 + `rename`,
/// 走到这里说明传错了类型(调用方的 bug)。
#[must_use]
pub fn closed_enum_schema<T: Serialize>(all: &[T], description: &str) -> RefOr<Schema> {
    let values: Vec<String> = all
        .iter()
        .map(|variant| {
            serde_json::to_value(variant)
                .ok()
                .and_then(|json| json.as_str().map(str::to_owned))
                .expect("闭集枚举序列化为字符串")
        })
        .collect();
    ObjectBuilder::new()
        .schema_type(Type::String)
        .description(Some(description))
        .enum_values(Some(values))
        .into()
}

/// 给一个核心闭集枚举生成 OpenAPI schema。核心枚举在 `baserust-core`,孤儿规则不许在这里给它实现
/// utoipa 的 `ToSchema` —— 所以生成一个本地**标记类型**(schema 名 = 核心枚举名,取值 = 核心枚举的 `ALL`
/// 经 serde 序列化,与线格式同源不漂移),DTO 字段用 `#[schema(value_type = …)]` / `#[param(value_type = …)]` 指向它。
/// 用法:`closed_enum_to_schema!(RoleNameSchema => RoleName, RoleName::ALL, "描述");`;schema 名要和
/// 核心枚举名不同(Rust 侧改过名、线上名字不变)时写 `Marker => Enum as "SchemaName"`。
//
// 为什么是宏而不是泛型:每个核心枚举要一个**独立的具名类型**(schema 名 = 枚举名,
// `#[schema(value_type = …)]` 只认具名类型),还要给它实现外部 trait。泛型标记类型
// `ClosedEnumSchema<T>` 的 schema 名会带上泛型参数、且 `ToSchema::name` 拿不到 `T` 的短名,
// 所以只能按枚举逐个生成。宏内用全路径(指南允许宏里不 use)。
#[macro_export]
macro_rules! closed_enum_to_schema {
    ($marker:ident => $ty:ident, $all:expr, $desc:expr) => {
        $crate::closed_enum_to_schema!($marker => $ty as stringify!($ty), $all, $desc);
    };
    ($marker:ident => $ty:ident as $name:expr, $all:expr, $desc:expr) => {
        #[doc = concat!("[`", stringify!($ty), "`] 的 OpenAPI schema 标记类型(只用于 `value_type`)。")]
        pub struct $marker;

        impl utoipa::PartialSchema for $marker {
            fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                $crate::infra::http::schema::closed_enum_schema(&$all, $desc)
            }
        }
        impl utoipa::ToSchema for $marker {
            fn name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed($name)
            }
        }
    };
}
