//! `UserAdminService`:后台用户 CRUD 编排。壳套 idm 原语(身份权威在 idm),读侧富化 app.profiles。
//! 原子写靠 idm 侧本地事务(`create_with_roles`/`set_roles`);跨 repo(软删 + 撤会话)不组一个 tx。

use std::collections::HashMap;
use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::port::ProfileDirectory;
use super::types::{
    AdminUserView, CreateUserRequest, ListUsersFilter, ResetPasswordRequest, SetRolesRequest,
    UpdateUserRequest,
};
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};
use crate::infra::sort::SortOrder;
use idm::{PwHasher, RoleRepo, SessionRepo, UserRepo};

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
}

impl UserAdminService {
    pub fn new(
        users: Arc<dyn UserRepo>,
        roles: Arc<dyn RoleRepo>,
        sessions: Arc<dyn SessionRepo>,
        hasher: Arc<dyn PwHasher>,
        profiles: Arc<dyn ProfileDirectory>,
    ) -> Self {
        Self {
            users,
            roles,
            sessions,
            hasher,
            profiles,
        }
    }

    /// 列表:idm 单 schema 主查询(过滤 + 排序 + 分页)→ 批量富化 profile → `Page<AdminUserView>`。
    /// `page` 的 cursor + 非默认 sort 的 422 校验在 handler(此处只翻译参数)。
    pub async fn list(
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
                    roles: r.roles,
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
        let role_ids = self.resolve_role_ids(&req.roles).await?;
        let hash = self.hasher.hash(&req.password)?;
        let user = self
            .users
            .create_with_roles(&req.username, req.email.as_deref(), &hash, &role_ids, by)
            .await?;
        // roles = 调用方传入的名(已校验都存在);新号 display_name 通常 null。
        self.enrich_view(user, req.roles).await
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

    /// 全量设角色(原子替换)。名→id 解析(未知 → 422)。
    pub async fn set_roles(
        &self,
        id: Uuid,
        req: SetRolesRequest,
        by: Option<String>,
    ) -> Result<AdminUserView, AppError> {
        let role_ids = self.resolve_role_ids(&req.roles).await?;
        self.roles.set_roles(id, &role_ids, by).await?;
        self.get(id).await
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
        if let Err(e) = self.sessions.revoke_all(id, None).await {
            tracing::warn!(error = %e, user_id = %id, "改密后撤销会话失败(best-effort,不阻断)");
        }
        Ok(())
    }

    /// 角色名 → id 解析。未知名 → `Validation`(422)。
    async fn resolve_role_ids(&self, names: &[String]) -> Result<Vec<Uuid>, AppError> {
        let catalog = self.roles.list().await?;
        let by_name: HashMap<&str, Uuid> =
            catalog.iter().map(|r| (r.name.as_str(), r.id)).collect();
        names
            .iter()
            .map(|n| {
                by_name
                    .get(n.as_str())
                    .copied()
                    .ok_or_else(|| AppError::Validation(format!("unknown role: {n}")))
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
            roles,
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
    /// seed 角色 admin/editor/user;FakeHasher + 空富化目录。
    async fn test_service() -> UserAdminService {
        let mem_users = InMemoryUserRepo::new();
        let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
        for (n, d) in [("admin", "Admin"), ("editor", "Editor"), ("user", "User")] {
            mem_roles.upsert(n, d, None).await.unwrap();
        }
        UserAdminService::new(
            Arc::new(mem_users),
            Arc::new(mem_roles),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(StaticProfileDirectory::empty()),
        )
    }

    #[tokio::test]
    async fn create_then_list_and_set_roles() {
        let svc = test_service().await;
        let created = svc
            .create(
                CreateUserRequest {
                    username: "alice".into(),
                    email: Some("a@x.io".into()),
                    password: "password123".into(),
                    roles: vec!["admin".into()],
                },
                Some("root".into()),
            )
            .await
            .unwrap();
        assert_eq!(created.roles, vec!["admin".to_string()]);

        // 未知角色 → Validation(422)
        let e = svc
            .create(
                CreateUserRequest {
                    username: "z".into(),
                    email: None,
                    password: "password123".into(),
                    roles: vec!["ghost".into()],
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
                    roles: vec!["editor".into(), "user".into()],
                },
                None,
            )
            .await
            .unwrap();
        let mut r = after.roles.clone();
        r.sort();
        assert_eq!(r, vec!["editor".to_string(), "user".to_string()]);

        // 含未知角色的 set_roles → Validation(全量原子,不留半态)
        let e = svc
            .set_roles(
                created.id,
                SetRolesRequest {
                    roles: vec!["editor".into(), "ghost".into()],
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
}
