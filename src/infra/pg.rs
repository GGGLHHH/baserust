//! Postgres 适配器共用的小件:核心类型 → sea-query 的映射、租户事务。只给各模块 `adapters/postgres.rs`
//! 这类适配器用,核心(`kernel` / 各模块的 model/service/端口)不碰 sea-query / sqlx。

use sqlx::{PgPool, Postgres, Transaction};

use crate::kernel::sort::SortOrder;
use crate::kernel::tenant::TenantId;

/// 开一个**带租户上下文**的事务:`begin` 后立刻 `set_config('app.tenant_id', <tenant>, true)`。
///
/// 读写租户数据的 PG 仓储方法一律经它开事务(读方法也一样),再在业务 SQL 里**同时**写
/// `where tenant_id = $1`(走索引;RLS 是第二道防线)。第三个参数 `true` = 事务级:
/// commit / rollback 后连接上不留租户,连接还回池里不会串到下一个请求(以后加 PgBouncer 也安全)。
/// **禁止**会话级 `SET app.tenant_id`。
///
/// 没走它(没设 `app.tenant_id`)的查询在开了 RLS 的表上查不到、也写不进任何行。
/// 跨租户的后台任务 / 平台级读不走它,用 `AppState` 的 `*_system_pool`(BYPASSRLS 账号)。
pub async fn tenant_tx(
    pool: &PgPool,
    tenant: TenantId,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("select set_config('app.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

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
