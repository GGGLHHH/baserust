//! ProfileRepo 契约一致性:同一批断言对 InMemory 与 Pg 各跑一遍(镜像 widget_repo_conformance)。
//! 钉:upsert 建/替判别、替换全量覆盖、**created_* 保留**、updated_* 推进、get 回环。
//! 只断相对关系(updated_at >= created_at),不断绝对时间戳。
//!
//! 内存入口:默认 `cargo test`。PG 入口:`just test-pg`(--features pg-conformance)。

use baserust::features::profile::{ProfileFields, ProfileRepo};
use serde_json::Value;
use uuid::Uuid;

async fn profile_repo_contract(repo: &dyn ProfileRepo) {
    let uid = Uuid::now_v7();
    // 未建 → None
    assert!(repo.get(uid).await.unwrap().is_none());

    // 建:created=true,审计双落
    let avatar = Uuid::now_v7();
    let f1 = ProfileFields {
        display_name: Some("A Z".into()),
        phone: Some("110".into()),
        avatar_content_id: Some(avatar),
    };
    let (p1, created) = repo.upsert(uid, f1, Some("tester".into())).await.unwrap();
    assert!(created, "首次 upsert 应判别为建");
    assert_eq!(p1.user_id, uid);
    assert_eq!(p1.created_by.as_deref(), Some("tester"));
    assert_eq!(p1.updated_by.as_deref(), Some("tester"));
    assert_eq!(p1.avatar_content_id, Some(avatar));

    // 替:created=false;业务字段**全量覆盖**(未给=清空,含 avatar);created_* 保留;updated_* 推进
    let f2 = ProfileFields {
        display_name: Some("M".into()),
        phone: None,
        avatar_content_id: None,
    };
    let (p2, created) = repo.upsert(uid, f2, Some("other".into())).await.unwrap();
    assert!(!created, "二次 upsert 应判别为替");
    assert_eq!(
        p2.created_by.as_deref(),
        Some("tester"),
        "created_by 必须保留"
    );
    assert_eq!(p2.created_at, p1.created_at, "created_at 必须保留");
    assert_eq!(p2.updated_by.as_deref(), Some("other"));
    assert!(p2.updated_at >= p1.updated_at);
    assert!(p2.phone.is_none(), "全量替换:未给字段清空");
    assert!(
        p2.avatar_content_id.is_none(),
        "avatar 同受全量替换管辖(null 即解绑)"
    );
    assert_eq!(p2.display_name.as_deref(), Some("M"));

    // get 回环
    let g = repo.get(uid).await.unwrap().expect("已建应可读");
    assert_eq!(g.display_name.as_deref(), Some("M"));
    assert_eq!(g.created_by.as_deref(), Some("tester"));
}

#[tokio::test]
async fn memory_satisfies_profile_contract() {
    let repo = baserust::features::profile::InMemoryProfileRepo::new();
    profile_repo_contract(&repo).await;
}

/// upsert 经真实 upsert(不是手写 insert)emit 恰一条 `profile.updated`,payload 形状正确
/// (含 avatar 与无 avatar 两种 case);mark_published 后 poll 复空。
/// 内存↔PG 各自的入口(见下 + pg 侧)按同一批断言驱动,钉 parity(镜像 `profile_repo_contract` 的手法)。
#[tokio::test]
async fn memory_profile_upsert_emits_profile_updated_outbox_event() {
    use baserust::features::profile::{InMemoryAppOutbox, InMemoryProfileRepo};

    let repo = InMemoryProfileRepo::new();
    let outbox = InMemoryAppOutbox::sharing_with(&repo);
    assert!(
        outbox.poll_unpublished(100).await.unwrap().is_empty(),
        "初始应无残留事件"
    );

    // ── 建(有头像):payload.avatar_url = 相对头像端点路径(按 user_id)──
    let uid = Uuid::now_v7();
    let avatar = Uuid::now_v7();
    let f = ProfileFields {
        display_name: Some("A Z".into()),
        phone: Some("110".into()),
        avatar_content_id: Some(avatar),
    };
    repo.upsert(uid, f, Some("tester".into())).await.unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1, "恰一条 profile.updated");
    assert_eq!(rows[0].event_type, "profile.updated");
    assert_eq!(rows[0].aggregate_id, uid);
    assert_eq!(
        rows[0].payload["user_id"],
        serde_json::to_value(uid).unwrap()
    );
    assert_eq!(rows[0].payload["display_name"], "A Z");
    assert_eq!(
        rows[0].payload["avatar_url"],
        format!("/api/v1/frontend/profiles/{uid}/avatar")
    );
    outbox.mark_published(&[rows[0].id]).await.unwrap();
    assert!(
        outbox.poll_unpublished(100).await.unwrap().is_empty(),
        "mark_published 后应复空"
    );

    // ── 建(无头像):payload.avatar_url 悬空 → null ──
    let uid2 = Uuid::now_v7();
    let f2 = ProfileFields {
        display_name: None,
        phone: None,
        avatar_content_id: None,
    };
    repo.upsert(uid2, f2, None).await.unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].aggregate_id, uid2);
    assert_eq!(rows[0].payload["display_name"], Value::Null);
    assert_eq!(rows[0].payload["avatar_url"], Value::Null);
    outbox.mark_published(&[rows[0].id]).await.unwrap();
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());
}

// ponytail: InMemoryProfileRepo::upsert 恒 Ok(无失败分支——无唯一约束等可失败的校验),
// 故"失败路径不 push"在内存侧无可测场景(结构上不存在),不补假失败分支去凑一个测试。
// PG 侧有真实约束可触发失败(见 pg::pg_profile_upsert_rollback_leaves_no_outbox_row),那条钉住
// "整笔回滚、outbox 不残留"这个不变量。

// ── PG 入口(镜像 widget_repo_conformance 的 harness)──
#[cfg(feature = "pg-conformance")]
#[path = "support/mod.rs"]
mod support;

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{profile_repo_contract, support};
    use baserust::features::profile::{PgAppOutbox, PgProfileRepo, ProfileFields, ProfileRepo};
    use baserust::infra::error::AppError;
    use serde_json::Value;
    use uuid::Uuid;

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_profile_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let repo = baserust::features::profile::PgProfileRepo::new(pool);
        profile_repo_contract(&repo).await;
        Ok(())
    }

    /// 镜像内存侧 `memory_profile_upsert_emits_profile_updated_outbox_event`:同一批断言在 PG 上再跑
    /// 一遍(真实 upsert 驱动,含 avatar/无 avatar 两 case),钉内存↔PG parity。
    #[sqlx::test(migrations = false)]
    async fn pg_profile_upsert_emits_profile_updated_outbox_event(
        pool: sqlx::PgPool,
    ) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let repo = PgProfileRepo::new(pool.clone());
        let outbox = PgAppOutbox::new(pool);

        assert!(
            outbox.poll_unpublished(100).await.unwrap().is_empty(),
            "初始应无残留事件"
        );

        // ── 建(有头像):payload.avatar_url = 相对头像端点路径(按 user_id)──
        let uid = Uuid::now_v7();
        let avatar = Uuid::now_v7();
        let f = ProfileFields {
            display_name: Some("A Z".into()),
            phone: Some("110".into()),
            avatar_content_id: Some(avatar),
        };
        repo.upsert(uid, f, Some("tester".into())).await.unwrap();
        let rows = outbox.poll_unpublished(100).await.unwrap();
        assert_eq!(rows.len(), 1, "恰一条 profile.updated");
        assert_eq!(rows[0].event_type, "profile.updated");
        assert_eq!(rows[0].aggregate_id, uid);
        assert_eq!(
            rows[0].payload["user_id"],
            serde_json::to_value(uid).unwrap()
        );
        assert_eq!(rows[0].payload["display_name"], "A Z");
        assert_eq!(
            rows[0].payload["avatar_url"],
            format!("/api/v1/frontend/profiles/{uid}/avatar")
        );
        outbox.mark_published(&[rows[0].id]).await.unwrap();
        assert!(
            outbox.poll_unpublished(100).await.unwrap().is_empty(),
            "mark_published 后应复空"
        );

        // ── 建(无头像):payload.avatar_url 悬空 → null ──
        let uid2 = Uuid::now_v7();
        let f2 = ProfileFields {
            display_name: None,
            phone: None,
            avatar_content_id: None,
        };
        repo.upsert(uid2, f2, None).await.unwrap();
        let rows = outbox.poll_unpublished(100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].aggregate_id, uid2);
        assert_eq!(rows[0].payload["display_name"], Value::Null);
        assert_eq!(rows[0].payload["avatar_url"], Value::Null);
        outbox.mark_published(&[rows[0].id]).await.unwrap();
        assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());
        Ok(())
    }

    /// **原子性**:强制 upsert 写 profiles 行本身失败(临时 CHECK 约束命中特定 display_name)→
    /// 整笔事务回滚:profiles 无残留行、outbox 无残留行。镜像 widget `create_with_tags` 的
    /// tx-rollback 断言手法(那边靠业务唯一索引触发,这里 profiles 表本身无额外约束可借,故显式
    /// 造一条临时 CHECK 来触发同等的"写入中途失败"场景)。
    #[sqlx::test(migrations = false)]
    async fn pg_profile_upsert_rollback_leaves_no_outbox_row(
        pool: sqlx::PgPool,
    ) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        sqlx::query(
            "alter table profiles add constraint profile_repo_conformance_force_fail \
             check (display_name is distinct from '__force_fail__')",
        )
        .execute(&pool)
        .await?;

        let repo = PgProfileRepo::new(pool.clone());
        let outbox = PgAppOutbox::new(pool);

        let uid = Uuid::now_v7();
        let f = ProfileFields {
            display_name: Some("__force_fail__".into()),
            phone: None,
            avatar_content_id: None,
        };
        let err = repo.upsert(uid, f, None).await.unwrap_err();
        assert!(matches!(err, AppError::Internal(_)));
        assert!(
            outbox.poll_unpublished(100).await.unwrap().is_empty(),
            "失败的 upsert 不该留下 outbox 行"
        );
        assert!(
            repo.get(uid).await.unwrap().is_none(),
            "失败的 upsert 也不该留下 profile 行(全有或全无)"
        );
        Ok(())
    }
}
