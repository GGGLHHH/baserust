//! `UserAdminService`:后台用户 CRUD 编排。壳套 idm 原语(身份权威在 idm),读侧富化 app.profiles。
//! 原子写靠 idm 侧本地事务(`create_with_roles`/`set_roles`);跨 repo(软删 + 撤会话)不组一个 tx。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::port::{ProfileDirectory, UserSearchFilter, UserSearchIndex};
use super::types::{
    AdminUserView, CreateUserRequest, ListUsersFilter, ResetPasswordRequest, RoleView,
    SetRolesRequest, UpdateUserRequest, UserSortField,
};
use crate::infra::authz::RoleName;
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};
use crate::infra::sort::SortOrder;
use idm::{PwHasher, RoleRepo, SessionRepo, UserRepo};

/// idm/投影侧的角色名串 → 闭集(唯一写者是 seed;未知值 = 数据异常,炸出来,见 closed-enums skill)。
fn parse_role_names(roles: Vec<String>) -> Vec<RoleName> {
    roles
        .into_iter()
        .map(|r| {
            r.parse()
                .expect("角色名恒为 RoleName 已知取值(仅由 seed 写入)")
        })
        .collect()
}

/// `SortOrder`(app 共享)→ idm 侧排序方向。SortOrder 是本 crate 类型,orphan 规则允许。
impl From<SortOrder> for idm::SortDir {
    fn from(o: SortOrder) -> Self {
        match o {
            SortOrder::Asc => idm::SortDir::Asc,
            SortOrder::Desc => idm::SortDir::Desc,
        }
    }
}

#[derive(Clone)]
pub struct UserAdminService {
    users: Arc<dyn UserRepo>,
    roles: Arc<dyn RoleRepo>,
    sessions: Arc<dyn SessionRepo>,
    hasher: Arc<dyn PwHasher>,
    profiles: Arc<dyn ProfileDirectory>,
    /// 只读检索投影(search 模块);None = 未接 search 后端 → list() 回退 idm 直查(q/DisplayName 排序 422)。
    search: Option<Arc<dyn UserSearchIndex>>,
}

impl UserAdminService {
    pub fn new(
        users: Arc<dyn UserRepo>,
        roles: Arc<dyn RoleRepo>,
        sessions: Arc<dyn SessionRepo>,
        hasher: Arc<dyn PwHasher>,
        profiles: Arc<dyn ProfileDirectory>,
        search: Option<Arc<dyn UserSearchIndex>>,
    ) -> Self {
        Self {
            users,
            roles,
            sessions,
            hasher,
            profiles,
            search,
        }
    }

    /// 列表:有 search 投影后端 → 走投影(支持 `q`/`display_name` 排序);无 → 回退 idm 直查
    /// (此时 `q`/`sort_by=display_name` → 422,因为回退路无法提供搜索能力)。
    /// `page` 的 cursor + 非默认 sort 的 422 校验在 handler(此处只翻译参数)。
    pub async fn list(
        &self,
        filter: &ListUsersFilter,
        page: PageParams,
    ) -> Result<Page<AdminUserView>, AppError> {
        match &self.search {
            Some(search) => self.list_via_projection(search.clone(), filter, page).await,
            None => {
                let wants_search = filter.q.as_deref().is_some_and(|s| !s.trim().is_empty())
                    || matches!(filter.sort_by, UserSortField::DisplayName);
                if wants_search {
                    return Err(AppError::Validation(
                        "search requires projection backend".into(),
                    ));
                }
                self.list_via_idm(filter, page).await
            }
        }
    }

    /// 投影路:走 search 索引(`q`/角色/时间过滤 + 4 键排序)→ 批量富化 avatar(投影不存 avatar)。
    async fn list_via_projection(
        &self,
        search: Arc<dyn UserSearchIndex>,
        filter: &ListUsersFilter,
        page: PageParams,
    ) -> Result<Page<AdminUserView>, AppError> {
        let sf = UserSearchFilter {
            username: filter.username.clone(),
            q: filter.q.clone(),
            roles_any: filter.roles_any(),
            roles_none: filter.roles_none(),
            created_from: filter.created_from,
            created_to: filter.created_to,
        };
        let result = search
            .query(&sf, filter.sort_by.to_search(), filter.order, &page)
            .await?;

        // avatar 富化(投影不存 avatar;display_name 取自投影):批量防 N+1,缺 → null。
        let ids: Vec<Uuid> = result.rows.iter().map(|r| r.id).collect();
        let briefs = self.profiles.batch(&ids).await?;
        let items: Vec<AdminUserView> = result
            .rows
            .into_iter()
            .map(|r| AdminUserView {
                id: r.id,
                username: r.username,
                email: r.email,
                email_verified: r.email_verified,
                created_at: r.created_at,
                roles: parse_role_names(r.roles),
                display_name: r.display_name, // 投影(可搜键)
                avatar_url: briefs.get(&r.id).and_then(|b| b.avatar_url.clone()), // 富化(display-only)
            })
            .collect();

        Ok(match page {
            PageParams::Offset { page, size, .. } => Page::offset(items, page, size, result.total),
            PageParams::Cursor { limit, .. } => {
                Page::cursor(items, limit, result.next_after.map(encode_cursor))
            }
        })
    }

    /// 回退路:idm 单 schema 主查询(过滤 + 排序 + 分页)→ 批量富化 profile → `Page<AdminUserView>`。
    /// 现有(pre-search)逻辑原样保留,不支持 `q`/`display_name` 排序(由 `list()` 提前 422)。
    async fn list_via_idm(
        &self,
        filter: &ListUsersFilter,
        page: PageParams,
    ) -> Result<Page<AdminUserView>, AppError> {
        let idm_filter = idm::UserListFilter {
            username: filter.username.clone(),
            roles_any: filter.roles_any(),
            roles_none: filter.roles_none(),
            created_from: filter.created_from,
            created_to: filter.created_to,
        };
        let idm_page = match &page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => idm::ListPage::Offset {
                offset: (page - 1) * size,
                limit: *size,
                with_total: *with_total,
            },
            PageParams::Cursor { after, limit } => idm::ListPage::Cursor {
                after: *after,
                limit: *limit,
            },
        };
        let result = self
            .users
            .list(
                &idm_filter,
                filter.sort_by.to_idm(),
                filter.order.into(),
                &idm_page,
            )
            .await?;

        // 富化:本页 user_id 一次 batch(防 N+1);缺 → display_name/avatar 降级 null。
        let ids: Vec<Uuid> = result.rows.iter().map(|r| r.id).collect();
        let briefs = self.profiles.batch(&ids).await?;
        let items: Vec<AdminUserView> = result
            .rows
            .into_iter()
            .map(|r| {
                let brief = briefs.get(&r.id);
                AdminUserView {
                    id: r.id,
                    username: r.username,
                    email: r.email,
                    email_verified: r.email_verified,
                    created_at: r.created_at,
                    roles: parse_role_names(r.roles),
                    display_name: brief.and_then(|b| b.display_name.clone()),
                    avatar_url: brief.and_then(|b| b.avatar_url.clone()),
                }
            })
            .collect();

        Ok(match page {
            PageParams::Offset { page, size, .. } => Page::offset(items, page, size, result.total),
            PageParams::Cursor { limit, .. } => {
                Page::cursor(items, limit, result.next_after.map(encode_cursor))
            }
        })
    }

    /// 建号(原子含角色)。名→id 解析(未知 → 422)→ hash → idm 事务建。
    pub async fn create(
        &self,
        req: CreateUserRequest,
        by: Option<String>,
    ) -> Result<AdminUserView, AppError> {
        req.validate()?;
        // 去重角色 id(保序):create_with_roles 靠 ON CONFLICT 去重,响应须与落库一致
        // (否则传 [admin, admin] 会让 201 回显两个 admin)。
        let mut seen = HashSet::new();
        let role_ids: Vec<Uuid> = req
            .roles
            .iter()
            .copied()
            .filter(|id| seen.insert(*id))
            .collect();
        // 传入的是角色 id:校验都存在(未知 → 422),并取其名字组装视图。
        let role_names = self.resolve_role_names(&role_ids).await?;
        let hash = self.hasher.hash(&req.password)?;
        let user = self
            .users
            .create_with_roles(&req.username, req.email.as_deref(), &hash, &role_ids, by)
            .await?;
        // 新号 display_name 通常 null。
        self.enrich_view(user, role_names).await
    }

    /// 详情。不存在/软删 → 404。
    pub async fn get(&self, id: Uuid) -> Result<AdminUserView, AppError> {
        let user = self.users.find_by_id(id).await?;
        let roles = self.roles.roles_for_user(id).await?;
        self.enrich_view(user, roles).await
    }

    /// 改身份(PUT 全量)。
    pub async fn update(
        &self,
        id: Uuid,
        req: UpdateUserRequest,
        by: Option<String>,
    ) -> Result<AdminUserView, AppError> {
        req.validate()?;
        let user = self
            .users
            .update(id, &req.username, req.email.as_deref(), by)
            .await?;
        let roles = self.roles.roles_for_user(id).await?;
        self.enrich_view(user, roles).await
    }

    /// 软删 + best-effort 撤会话(失败仅 warn,不阻断:用户已删,refresh 下次必失败)。
    pub async fn delete(&self, id: Uuid, by: Option<String>) -> Result<(), AppError> {
        self.users.soft_delete(id, by).await?;
        if let Err(e) = self.sessions.revoke_all(id, None).await {
            tracing::warn!(error = %e, user_id = %id, "软删后撤销会话失败(best-effort,不阻断)");
        }
        Ok(())
    }

    /// 全量设角色(原子替换)。传角色 id;未知 id → 422。
    pub async fn set_roles(
        &self,
        id: Uuid,
        req: SetRolesRequest,
        by: Option<String>,
    ) -> Result<AdminUserView, AppError> {
        // 先确认用户存在(不存在/软删 → 404):否则空 roles 会对幽灵/软删用户做空替换 +
        // 发 outbox 事件,却仍在末尾 get() 才报 404(幽灵事件 + 清掉软删用户的角色行)。
        self.users.find_by_id(id).await?;
        // 校验 id 都存在(未知 → 422),再原子替换。get() 会重取名字组装视图。
        self.resolve_role_names(&req.roles).await?;
        self.roles.set_roles(id, &req.roles, by).await?;
        self.get(id).await
    }

    /// 角色目录(admin 分配候选)。全量存活角色,包成单页游标(角色小而有界,不真分页)。
    pub async fn list_roles(&self) -> Result<Page<RoleView>, AppError> {
        let items: Vec<RoleView> = self
            .roles
            .list()
            .await?
            .into_iter()
            .map(RoleView::from)
            .collect();
        let limit = items.len().max(1) as u64;
        Ok(Page::cursor(items, limit, None))
    }

    /// 管理员重置密码 + best-effort 撤会话(强制重新登录;撤失败仅 warn)。
    pub async fn reset_password(
        &self,
        id: Uuid,
        req: ResetPasswordRequest,
    ) -> Result<(), AppError> {
        req.validate()?;
        let hash = self.hasher.hash(&req.new_password)?;
        self.users.update_password(id, &hash).await?;
        // 撤会话 fail-closed(区别于 delete 的 best-effort):refresh 路径不验密码,撤失败=旧 refresh
        // 会话仍可续签 → 改密到 refresh TTL 才真生效。对齐 idm 自助 change_password(那边也 `?`)。
        self.sessions.revoke_all(id, None).await?;
        Ok(())
    }

    /// 角色 id → name 解析。校验每个 id 都在存活目录里,未知 id → `Validation`(422)。
    /// 返回名字集(顺序同入参),供 `AdminUserView.roles`(名字)组装 / 单纯校验。
    async fn resolve_role_names(&self, ids: &[Uuid]) -> Result<Vec<String>, AppError> {
        let catalog = self.roles.list().await?;
        let by_id: HashMap<Uuid, &str> = catalog.iter().map(|r| (r.id, r.name.as_str())).collect();
        ids.iter()
            .map(|id| {
                by_id
                    .get(id)
                    .map(|n| n.to_string())
                    .ok_or_else(|| AppError::Validation(format!("unknown role: {id}")))
            })
            .collect()
    }

    /// 组 `AdminUserView`(单用户 + 一次 profile 富化)。
    async fn enrich_view(
        &self,
        user: idm::User,
        roles: Vec<String>,
    ) -> Result<AdminUserView, AppError> {
        let briefs = self.profiles.batch(&[user.id]).await?;
        let brief = briefs.get(&user.id);
        Ok(AdminUserView {
            id: user.id,
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
            created_at: user.created_at,
            roles: parse_role_names(roles),
            display_name: brief.and_then(|b| b.display_name.clone()),
            avatar_url: brief.and_then(|b| b.avatar_url.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::users::port::StaticProfileDirectory;
    use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

    /// 内存装配:user/role repo **共享** RoleStore(否则新号角色对 list/roles_for_user 不可见);
    /// seed 角色 superadmin/admin/user(闭集);FakeHasher + 空富化目录。
    async fn test_service() -> UserAdminService {
        let mem_users = InMemoryUserRepo::new();
        let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
        for (n, d) in [
            ("superadmin", "Superadmin"),
            ("admin", "Admin"),
            ("user", "User"),
        ] {
            mem_roles.upsert(n, d, None).await.unwrap();
        }
        UserAdminService::new(
            Arc::new(mem_users),
            Arc::new(mem_roles),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(StaticProfileDirectory::empty()),
            None,
        )
    }

    #[tokio::test]
    async fn create_then_list_and_set_roles() {
        let svc = test_service().await;
        // 角色现按 id 传;从目录按名取 id(存活名唯一)。
        let catalog = svc.list_roles().await.unwrap();
        let rid = |name: &str| {
            catalog
                .items
                .iter()
                .find(|r| r.name.as_str() == name)
                .unwrap()
                .id
        };
        let created = svc
            .create(
                CreateUserRequest {
                    username: "alice".into(),
                    email: Some("a@x.io".into()),
                    password: "password123".into(),
                    roles: vec![rid("admin")],
                },
                Some("root".into()),
            )
            .await
            .unwrap();
        assert_eq!(created.roles, vec![RoleName::Admin]);

        // 未知角色 → Validation(422)
        let e = svc
            .create(
                CreateUserRequest {
                    username: "z".into(),
                    email: None,
                    password: "password123".into(),
                    roles: vec![Uuid::now_v7()],
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::Validation(_)));

        // set_roles 全量替换
        let after = svc
            .set_roles(
                created.id,
                SetRolesRequest {
                    roles: vec![rid("superadmin"), rid("user")],
                },
                None,
            )
            .await
            .unwrap();
        let mut r = after.roles.clone();
        r.sort_by_key(|x| x.as_str());
        assert_eq!(r, vec![RoleName::Superadmin, RoleName::User]);

        // 含未知角色的 set_roles → Validation(全量原子,不留半态)
        let e = svc
            .set_roles(
                created.id,
                SetRolesRequest {
                    roles: vec![rid("superadmin"), Uuid::now_v7()],
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::Validation(_)));

        // list 命中(username 模糊 + offset)
        let page = svc
            .list(
                &ListUsersFilter {
                    username: Some("ali".into()),
                    ..Default::default()
                },
                PageParams::Offset {
                    page: 1,
                    size: 20,
                    with_total: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].username, "alice");
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let svc = test_service().await;
        assert!(matches!(
            svc.get(Uuid::now_v7()).await,
            Err(AppError::NotFound)
        ));
    }

    /// set_roles 对不存在用户先报 404,不做写(空 roles 也不许漏过去空替换 + 发事件)。
    #[tokio::test]
    async fn set_roles_on_missing_user_is_404_before_mutating() {
        let svc = test_service().await;
        let err = svc
            .set_roles(Uuid::now_v7(), SetRolesRequest { roles: vec![] }, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }

    /// create 传重复角色 id:响应 roles 去重(与 idm ON CONFLICT 落库一致,不回显两遍)。
    #[tokio::test]
    async fn create_dedups_duplicate_role_ids_in_response() {
        let svc = test_service().await;
        let catalog = svc.list_roles().await.unwrap();
        let admin = catalog
            .items
            .iter()
            .find(|r| r.name == RoleName::Admin)
            .unwrap()
            .id;
        let created = svc
            .create(
                CreateUserRequest {
                    username: "dup".into(),
                    email: None,
                    password: "password123".into(),
                    roles: vec![admin, admin],
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(created.roles, vec![RoleName::Admin]);
    }

    fn offset_page() -> PageParams {
        PageParams::Offset {
            page: 1,
            size: 20,
            with_total: true,
        }
    }

    #[tokio::test]
    async fn list_without_search_backend_rejects_q_and_display_name_sort() {
        let svc = test_service().await;

        let e = svc
            .list(
                &ListUsersFilter {
                    q: Some("x".into()),
                    ..Default::default()
                },
                offset_page(),
            )
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::Validation(_)));

        let e = svc
            .list(
                &ListUsersFilter {
                    sort_by: UserSortField::DisplayName,
                    ..Default::default()
                },
                offset_page(),
            )
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn list_without_search_backend_and_plain_filter_falls_back_to_idm() {
        let svc = test_service().await;
        svc.create(
            CreateUserRequest {
                username: "bob".into(),
                email: None,
                password: "password123".into(),
                roles: vec![],
            },
            None,
        )
        .await
        .unwrap();

        let page = svc
            .list(&ListUsersFilter::default(), offset_page())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].username, "bob");
    }

    /// 钉死 `list()` 的 422 门是 `.trim().is_empty()` 而非 `.is_empty()`——纯空白 `q` 不该被当成
    /// "要搜索" 拦下,应落回 idm 直查路(无 search 后端也能正常翻页)。
    #[tokio::test]
    async fn list_without_search_backend_whitespace_q_falls_back_to_idm_not_422() {
        let svc = test_service().await;
        svc.create(
            CreateUserRequest {
                username: "dora".into(),
                email: None,
                password: "password123".into(),
                roles: vec![],
            },
            None,
        )
        .await
        .unwrap();

        let page = svc
            .list(
                &ListUsersFilter {
                    q: Some("   ".into()),
                    ..Default::default()
                },
                offset_page(),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].username, "dora");
    }

    /// 假 search 后端:忽略入参,原样回放预置行(测投影分支的映射/富化,不测查询语义)。
    struct FakeSearchIndex {
        rows: Vec<super::super::port::UserSearchRow>,
    }

    #[async_trait::async_trait]
    impl UserSearchIndex for FakeSearchIndex {
        async fn query(
            &self,
            _filter: &UserSearchFilter,
            _sort: super::super::port::UserSearchSort,
            _order: SortOrder,
            _page: &PageParams,
        ) -> Result<super::super::port::UserSearchPage, AppError> {
            Ok(super::super::port::UserSearchPage {
                rows: self.rows.clone(),
                total: Some(self.rows.len() as u64),
                next_after: None,
            })
        }
    }

    #[tokio::test]
    async fn list_with_search_backend_uses_projection_and_enriches_avatar() {
        use super::super::port::{ProfileBrief, UserSearchRow};

        let id = Uuid::now_v7();
        let mut avatar_seed = HashMap::new();
        avatar_seed.insert(
            id,
            ProfileBrief {
                // 富化目录也带 display_name,但投影路必须优先用投影自带的值,不应被覆盖。
                display_name: Some("should-not-be-used".into()),
                avatar_url: Some("avatar.png".into()),
            },
        );

        let mem_users = InMemoryUserRepo::new();
        let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
        let svc = UserAdminService::new(
            Arc::new(mem_users),
            Arc::new(mem_roles),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(StaticProfileDirectory(avatar_seed)),
            Some(Arc::new(FakeSearchIndex {
                rows: vec![UserSearchRow {
                    id,
                    username: "carol".into(),
                    email: Some("c@x.io".into()),
                    email_verified: true,
                    created_at: time::OffsetDateTime::now_utc(),
                    roles: vec!["user".into()],
                    display_name: Some("Carol Projection".into()),
                }],
            })),
        );

        let page = svc
            .list(
                &ListUsersFilter {
                    q: Some("carol".into()),
                    ..Default::default()
                },
                offset_page(),
            )
            .await
            .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].username, "carol");
        assert_eq!(
            page.items[0].display_name.as_deref(),
            Some("Carol Projection")
        );
        assert_eq!(page.items[0].avatar_url.as_deref(), Some("avatar.png"));
    }

    /// 假 search 后端:记录收到的 `UserSearchFilter`(测 `list_via_projection` 组 filter 时是否把
    /// `username` 也透传给底层——回归点:曾经只传 `q`,`username` 被静默丢弃)。
    struct RecordingSearchIndex {
        received: std::sync::Mutex<Option<UserSearchFilter>>,
    }

    #[async_trait::async_trait]
    impl UserSearchIndex for RecordingSearchIndex {
        async fn query(
            &self,
            filter: &UserSearchFilter,
            _sort: super::super::port::UserSearchSort,
            _order: SortOrder,
            _page: &PageParams,
        ) -> Result<super::super::port::UserSearchPage, AppError> {
            *self.received.lock().expect("锁未中毒") = Some(filter.clone());
            Ok(super::super::port::UserSearchPage {
                rows: vec![],
                total: Some(0),
                next_after: None,
            })
        }
    }

    #[tokio::test]
    async fn list_via_projection_passes_username_filter_through() {
        let mem_users = InMemoryUserRepo::new();
        let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
        let recorder = Arc::new(RecordingSearchIndex {
            received: std::sync::Mutex::new(None),
        });
        let svc = UserAdminService::new(
            Arc::new(mem_users),
            Arc::new(mem_roles),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(StaticProfileDirectory::empty()),
            Some(recorder.clone()),
        );

        svc.list(
            &ListUsersFilter {
                username: Some("alice".into()),
                q: Some("wonder".into()),
                ..Default::default()
            },
            offset_page(),
        )
        .await
        .unwrap();

        let got = recorder
            .received
            .lock()
            .expect("锁未中毒")
            .clone()
            .expect("query 应被调用一次");
        assert_eq!(
            got.username.as_deref(),
            Some("alice"),
            "username 过滤应透传给投影后端,不该被静默丢弃"
        );
        assert_eq!(got.q.as_deref(), Some("wonder"));
    }
}
