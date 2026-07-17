//! 内存实现 —— 脚手架默认,无需数据库即可跑通全链路。
//! 镜像 PG 的「memberships 过滤 suspended/软删 + seq 升序 + is_active 标记」语义
//! (conformance 对拍钉住)。

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::TenantRepo;
use crate::features::tenants::types::{
    Membership, Tenant, TenantMemberFact, TenantRole, TenantStatus,
};
use crate::infra::error::AppError;

/// 只存**本实现的语义需要**的字段。
///
/// `created_by` 存(替换时要保留它,是真读路径);`updated_by` **不存** —— 它每次替换都被
/// 无条件覆盖、既不参与保留语义、端口也不暴露,存了就是死字段(编译器会直接说
/// "field is never read",而 clippy 是 -D warnings)。PG 侧那一列照写不误。
///
/// 这不是「内存把 by 吞了」:P2 若给 `Membership` 加审计字段,内存的 `alive_membership`
/// 会因缺字段**编译不过**,类型系统会逼这里补上 —— 不需要现在预先存死数据来防它。
struct TenantRow {
    name: String,
    display_name: String,
    status: TenantStatus,
    created_by: Option<String>,
    deleted_at: Option<OffsetDateTime>,
    /// P6 的 `Tenant` DTO 要回 created_at/updated_at。PG 侧用 `now()`/触发器,内存用
    /// `now_utc()` —— conformance 只断言相对关系(updated_at >= created_at),不断绝对值。
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

struct MemberRow {
    role: TenantRole,
    /// 排序键(`Uuid::now_v7()`)。**替换角色时冻结** —— 见 repo/mod.rs 的 upsert_member doc。
    seq: Uuid,
    granted_by: Option<String>,
    granted_at: OffsetDateTime,
}

/// 一把锁覆盖三张表 —— 与 PG 侧同一个原子段口径(镜像 widget 的 MemStore 手法)。
#[derive(Default)]
struct MemStore {
    tenants: HashMap<Uuid, TenantRow>,
    /// (user_id, tenant_id) -> MemberRow
    members: HashMap<(Uuid, Uuid), MemberRow>,
    active: HashMap<Uuid, Uuid>,
}

pub struct InMemoryTenantRepo {
    store: Mutex<MemStore>,
}

impl InMemoryTenantRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(MemStore::default()),
        }
    }

    /// **仅本模块单元测试**:把租户标成软删。
    ///
    /// 生产 trait 刻意没有软删方法(P1 无消费方,YAGNI)——但 `memberships` 过滤软删租户是
    /// spec §4.4 唯一点名的「安全支点」。没有这个口子,内存侧造不出该状态,这条分支就只能靠
    /// `just test-pg` 验 —— 而它**不在** CLAUDE.md 要求的 `just check && just test && just lint`
    /// 三条命令里,还需要本地起 PG。**YAGNI 只该挡生产 API,不该挡测试可达性。**
    ///
    /// 放 `#[cfg(test)]` + 同文件单元测试(而非 `tests/` 下的共享契约):集成测试链接的是
    /// 正常编译的 lib,`cfg(test)` 对它不可见。PG 侧的对应覆盖是
    /// `pg_memberships_filters_soft_deleted_tenant`(raw SQL 直接盖 deleted_at)——
    /// 两侧各用自己够得着的机制覆盖同一条契约,且**默认 `just test` 就能跑到内存这半**。
    #[cfg(test)]
    fn soft_delete_tenant_for_test(&self, id: Uuid) {
        if let Some(t) = self.store.lock().expect("锁未中毒").tenants.get_mut(&id) {
            t.deleted_at = Some(OffsetDateTime::now_utc());
        }
    }
}

impl Default for InMemoryTenantRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStore {
    /// 镜像 PG 的 `join tenants where deleted_at is null and status = 'active'`,
    /// 并用 `left join user_active_tenant` 的等价逻辑算 is_active。
    /// 这是契约,不是优化 —— 见 repo/mod.rs 的 `memberships` doc。
    ///
    /// 收 `(user_id, tenant_id)` 自己查,**不收调用方已持有的 `&MemberRow`**:那样能省一次
    /// HashMap 查找,但 tenant_id 与 MemberRow 就被解耦了 —— 传错组合能编译过,产出一个
    /// 张冠李戴的 `Membership`。这里 N 小到那次查找无所谓(见 `memberships` 的 ponytail 注),
    /// 不值当拿类型安全换。
    fn alive_membership(&self, user_id: Uuid, tenant_id: Uuid) -> Option<Membership> {
        let m = self.members.get(&(user_id, tenant_id))?;
        let t = self.tenants.get(&tenant_id)?;
        if t.deleted_at.is_some() || t.status != TenantStatus::Active {
            return None;
        }
        Some(Membership {
            tenant_id,
            name: t.name.clone(),
            display_name: t.display_name.clone(),
            role: m.role,
            is_active: self.active.get(&user_id) == Some(&tenant_id),
        })
    }

    /// 存活租户 → `Tenant` DTO(不含 deleted_at)。软删的返回 None。
    fn alive_tenant(&self, id: Uuid) -> Option<Tenant> {
        let t = self.tenants.get(&id)?;
        if t.deleted_at.is_some() {
            return None;
        }
        Some(Tenant {
            id,
            name: t.name.clone(),
            display_name: t.display_name.clone(),
            status: t.status,
            created_at: t.created_at,
            updated_at: t.updated_at,
        })
    }
}

#[async_trait]
impl TenantRepo for InMemoryTenantRepo {
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        // ponytail: O(全库成员数) 全扫。内存实现只跑 dev/测试(prod 恒 PG),N 小到无所谓;
        // 真要 O(该用户成员数),把 members 改成 HashMap<Uuid, HashMap<Uuid, MemberRow>> 分桶。
        let mut rows: Vec<(Uuid, Membership)> = store
            .members
            .iter()
            .filter(|((u, _), _)| *u == user_id)
            .filter_map(|((u, t), m)| store.alive_membership(*u, *t).map(|ms| (m.seq, ms)))
            .collect();
        // seq 升序(镜像 PG 的 `order by m.seq`)。v7 严格全序 ⇒ 不会打平,无需 tiebreak。
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(rows.into_iter().map(|(_, m)| m).collect())
    }

    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        Ok(store.alive_membership(user_id, tenant_id))
    }

    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .active
            .insert(user_id, tenant_id);
        Ok(())
    }

    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let existing = store.tenants.get(&id);
        // deleted_at:新建为 None;已存在则**保留原值**,不因重跑 upsert 静默复活软删租户。
        // created_by:建时落、替时**保留**(镜像 PG 的 conflict 分支不碰该列)。
        // updated_by:不存,理由见 TenantRow 的 doc(PG 侧照写)。
        let deleted_at = existing.and_then(|t| t.deleted_at);
        let created_by = match existing {
            Some(t) => t.created_by.clone(),
            None => by,
        };
        let created_at = existing.map_or_else(OffsetDateTime::now_utc, |t| t.created_at);
        store.tenants.insert(
            id,
            TenantRow {
                name: name.to_string(),
                display_name: display_name.to_string(),
                status,
                created_by,
                deleted_at,
                created_at,
                updated_at: OffsetDateTime::now_utc(),
            },
        );
        Ok(())
    }

    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 替换只改 role;seq/granted_at/granted_by 三者冻结 —— 它们共同描述「何时、被谁加进来」
        // 这一次事件,改角色不让它重新发生。见 repo/mod.rs 的 upsert_member doc。
        let existing = store.members.get(&(user_id, tenant_id));
        let (seq, granted_at, granted_by) = match existing {
            Some(m) => (m.seq, m.granted_at, m.granted_by.clone()),
            None => (Uuid::now_v7(), OffsetDateTime::now_utc(), by),
        };
        store.members.insert(
            (user_id, tenant_id),
            MemberRow {
                role,
                seq,
                granted_by,
                granted_at,
            },
        );
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut rows: Vec<(OffsetDateTime, Tenant)> = store
            .tenants
            .keys()
            .filter_map(|id| store.alive_tenant(*id))
            .map(|t| (t.created_at, t))
            .collect();
        // created_at desc(镜像 PG 的 order by created_at desc)。now_utc() 同毫秒可能打平,
        // 用 id 兜底定序(HashMap 迭代无序,否则同刻建的两个租户列表顺序会飘)。
        rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.id.cmp(&a.1.id)));
        Ok(rows.into_iter().map(|(_, t)| t).collect())
    }

    async fn get_tenant(&self, id: Uuid) -> Result<Option<Tenant>, AppError> {
        Ok(self.store.lock().expect("锁未中毒").alive_tenant(id))
    }

    async fn create_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        by: Option<String>,
    ) -> Result<Tenant, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 存活行内 name 唯一(镜像 PG 的 tenants_name_alive_uidx)→ 重名 Conflict(409)。
        // 这是端口契约的一部分(create 与 upsert 的区别就在这),故内存也必须查 —— 不是
        // trait 头「已知分歧」里那种「只 PG 强制」的约束。
        if store
            .tenants
            .values()
            .any(|t| t.deleted_at.is_none() && t.name == name)
        {
            return Err(AppError::Conflict("tenant name already exists".to_owned()));
        }
        let now = OffsetDateTime::now_utc();
        store.tenants.insert(
            id,
            TenantRow {
                name: name.to_string(),
                display_name: display_name.to_string(),
                status: TenantStatus::Active, // 建时恒 active(镜像 PG)
                created_by: by,
                deleted_at: None,
                created_at: now,
                updated_at: now,
            },
        );
        Ok(store.alive_tenant(id).expect("刚插入的存活租户"))
    }

    async fn update_tenant(
        &self,
        id: Uuid,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<Tenant, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 只动存活行(镜像 PG 的 where deleted_at is null);不存在/已软删 → NotFound。
        match store.tenants.get_mut(&id) {
            Some(t) if t.deleted_at.is_none() => {
                t.display_name = display_name.to_string();
                t.status = status;
                let _ = by; // updated_by 内存不存,理由见 TenantRow 的 doc(PG 侧照写)
                t.updated_at = OffsetDateTime::now_utc();
            }
            _ => return Err(AppError::NotFound),
        }
        Ok(store.alive_tenant(id).expect("刚更新的存活租户"))
    }

    async fn members_of(&self, tenant_id: Uuid) -> Result<Vec<TenantMemberFact>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut rows: Vec<(Uuid, TenantMemberFact)> = store
            .members
            .iter()
            .filter(|((_, t), _)| *t == tenant_id)
            .map(|((u, _), m)| {
                (
                    m.seq,
                    TenantMemberFact {
                        user_id: *u,
                        role: m.role,
                        granted_at: m.granted_at,
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0)); // seq 升序(镜像 PG 的 order by seq)
        Ok(rows.into_iter().map(|(_, m)| m).collect())
    }

    async fn remove_member(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        let removed = self
            .store
            .lock()
            .expect("锁未中毒")
            .members
            .remove(&(user_id, tenant_id));
        if removed.is_none() {
            return Err(AppError::NotFound); // 不是成员 → NotFound(镜像 PG 的 rows_affected == 0)
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **软删过滤的内存侧覆盖** —— 与 PG 侧的 `pg_memberships_filters_soft_deleted_tenant`
    /// 成对。这条分支是 spec §4.4 唯一点名的「安全支点」(停用/软删租户必须真的切断访问),
    /// 而 `tests/` 下的共享契约造不出软删状态(trait 无该方法、cfg(test) 对集成测试不可见)。
    /// 放这里的意义:**`just test` 默认就跑**,不必等 `just test-pg`。
    #[tokio::test]
    async fn memberships_filters_soft_deleted_tenant() {
        let repo = InMemoryTenantRepo::new();
        let (user, t) = (Uuid::now_v7(), Uuid::now_v7());
        repo.upsert_tenant(t, "gone", "Gone", TenantStatus::Active, None)
            .await
            .unwrap();
        repo.upsert_member(user, t, TenantRole::Admin, None)
            .await
            .unwrap();

        // 软删前:两条读路径都看得见
        assert!(repo.membership(user, t).await.unwrap().is_some());
        assert_eq!(repo.memberships(user).await.unwrap().len(), 1);

        repo.soft_delete_tenant_for_test(t);

        // 软删后:两条读路径都必须过滤掉它(空,而不只是「不含 t」——后者对空列表恒真)
        assert_eq!(repo.membership(user, t).await.unwrap(), None);
        assert_eq!(repo.memberships(user).await.unwrap(), vec![]);
    }

    /// `upsert_tenant` 不复活软删租户 —— 与 PG 侧的
    /// `pg_upsert_tenant_does_not_revive_soft_deleted` 成对(理由同上:seed 每次启动都重跑)。
    #[tokio::test]
    async fn upsert_tenant_does_not_revive_soft_deleted() {
        let repo = InMemoryTenantRepo::new();
        let (user, t) = (Uuid::now_v7(), Uuid::now_v7());
        repo.upsert_tenant(t, "zombie", "Zombie", TenantStatus::Active, None)
            .await
            .unwrap();
        repo.upsert_member(user, t, TenantRole::Admin, None)
            .await
            .unwrap();
        repo.soft_delete_tenant_for_test(t);

        // 模拟 seed::apply 每次启动的重跑
        repo.upsert_tenant(t, "zombie", "Zombie", TenantStatus::Active, None)
            .await
            .unwrap();

        assert_eq!(
            repo.membership(user, t).await.unwrap(),
            None,
            "upsert_tenant 不得静默复活软删租户"
        );
    }

    /// `by` 的**保留语义**在内存侧与 PG 一致:created_by 替时保留、granted_by 改角色时冻结。
    /// 端口不暴露这些列,故直接查内部 store —— PG 侧的对照是 `pg_audit_columns`。
    /// (`updated_by` 内存不存,理由见 `TenantRow` 的 doc;PG 侧那半由 `pg_audit_columns` 钉。)
    #[tokio::test]
    async fn by_preserve_semantics_match_pg() {
        let repo = InMemoryTenantRepo::new();
        let (user, t) = (Uuid::now_v7(), Uuid::now_v7());

        repo.upsert_tenant(
            t,
            "acme",
            "Acme",
            TenantStatus::Active,
            Some("carol".into()),
        )
        .await
        .unwrap();
        repo.upsert_member(user, t, TenantRole::Admin, Some("carol".into()))
            .await
            .unwrap();
        // 先取基线 —— granted_at 的冻结要靠前后对比才钉得住,否则它是个没人读的仪式字段
        // (它唯一的「读」是保留逻辑读出来再原样写回自己 —— 那是自证循环,不是真读路径)
        let granted_at_0 = repo
            .store
            .lock()
            .unwrap()
            .members
            .get(&(user, t))
            .unwrap()
            .granted_at;

        // 替换租户 / 改角色,都用另一个 by
        repo.upsert_tenant(
            t,
            "acme",
            "Acme Inc",
            TenantStatus::Active,
            Some("bob".into()),
        )
        .await
        .unwrap();
        repo.upsert_member(user, t, TenantRole::Member, Some("bob".into()))
            .await
            .unwrap();

        let s = repo.store.lock().unwrap();
        assert_eq!(
            s.tenants.get(&t).unwrap().created_by.as_deref(),
            Some("carol"),
            "created_by 替时保留(建它的人不因后来谁改过而变)"
        );
        let m = s.members.get(&(user, t)).unwrap();
        assert_eq!(
            m.granted_by.as_deref(),
            Some("carol"),
            "改角色不得改 granted_by —— 否则拼出 'bob 在 carol 的时刻加的人' 这种伪造记录"
        );
        assert_eq!(
            m.granted_at, granted_at_0,
            "改角色不得重置 granted_at —— 它与 granted_by/seq 同属「何时被谁加进来」这一次事件"
        );
    }
}
