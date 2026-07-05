//! ProfileRepo 契约一致性:同一批断言对 InMemory 与 Pg 各跑一遍(镜像 widget_repo_conformance)。
//! 钉:upsert 建/替判别、替换全量覆盖、**created_* 保留**、updated_* 推进、get 回环。
//! 只断相对关系(updated_at >= created_at),不断绝对时间戳。
//!
//! 内存入口:默认 `cargo test`。PG 入口:`just test-pg`(--features pg-conformance)。

use uuid::Uuid;
use xchangeai::features::profile::{ProfileFields, ProfileRepo};

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
    let repo = xchangeai::features::profile::InMemoryProfileRepo::new();
    profile_repo_contract(&repo).await;
}

// ── PG 入口(镜像 widget_repo_conformance 的 harness)──
#[cfg(feature = "pg-conformance")]
#[path = "support/mod.rs"]
mod support;

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{profile_repo_contract, support};

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_profile_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let repo = xchangeai::features::profile::PgProfileRepo::new(pool);
        profile_repo_contract(&repo).await;
        Ok(())
    }
}
