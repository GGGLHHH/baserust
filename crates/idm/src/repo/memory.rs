//! idm 仓储内存实现 —— 脚手架默认,无 DB 即可跑通注册/登录全链路 + 写单测。
//! 镜像 PG 的软删过滤、username 唯一、email(有则)唯一,保 parity。

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{RoleRepo, Session, SessionRepo, User, UserRepo, UserWithHash};
use crate::error::IdmError;

/// 内存内部行:比 `User` 多 password_hash + deleted_at(DTO 不暴露)。
#[derive(Clone)]
struct UserRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    password_hash: String,
    deleted_at: Option<OffsetDateTime>,
}

impl UserRow {
    fn to_user(&self) -> User {
        User {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            email_verified: self.email_verified,
        }
    }
}

pub struct InMemoryUserRepo {
    store: Mutex<HashMap<Uuid, UserRow>>,
}

impl InMemoryUserRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryUserRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserRepo for InMemoryUserRepo {
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // username 唯一 + email(有则)唯一,仅对存活行:镜像两个 partial unique 索引。
        let dup = store.values().any(|r| {
            r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(IdmError::Conflict("用户名或邮箱已被占用".to_owned()));
        }
        let row = UserRow {
            id: Uuid::now_v7(),
            username: username.to_owned(),
            email: email.map(str::to_owned),
            email_verified: false,
            password_hash: password_hash.to_owned(),
            deleted_at: None,
        };
        let user = row.to_user();
        store.insert(row.id, row);
        Ok(user)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .values()
            .find(|r| {
                r.deleted_at.is_none()
                    && (r.username == identifier || r.email.as_deref() == Some(identifier))
            })
            .map(|r| UserWithHash {
                user: r.to_user(),
                password_hash: r.password_hash.clone(),
            }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .ok_or(IdmError::NotFound)
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        let store = self.store.lock().expect("锁未中毒");
        // 镜像 PG:只返存活行,查不到的 id 直接缺席(不报错)。
        Ok(ids
            .iter()
            .filter_map(|id| store.get(id))
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .collect())
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 冲突检查(排除自己):username / email 撞别的存活用户
        let dup = store.values().any(|r| {
            r.id != id
                && r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(IdmError::Conflict("用户名或邮箱已被占用".to_owned()));
        }
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                // PUT 全量替换:username 必填、email 总替换(含清空),替换 email 即重置验证。
                r.username = username.to_owned();
                r.email = email.map(str::to_owned);
                r.email_verified = false;
                Ok(r.to_user())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn soft_delete(&self, id: Uuid, _by: Option<String>) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                r.deleted_at = Some(OffsetDateTime::now_utc());
                Ok(())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&user_id) {
            Some(r) if r.deleted_at.is_none() => {
                r.password_hash = password_hash.to_owned();
                Ok(())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .get(&user_id)
            .filter(|r| r.deleted_at.is_none())
            .map(|r| r.password_hash.clone()))
    }
}

/// 会话内存行。
#[derive(Clone)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

pub struct InMemorySessionRepo {
    store: Mutex<Vec<SessionRow>>,
}

impl InMemorySessionRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemorySessionRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionRepo for InMemorySessionRepo {
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: OffsetDateTime,
        _by: Option<String>,
    ) -> Result<Session, IdmError> {
        let row = SessionRow {
            id: Uuid::now_v7(),
            user_id,
            token_hash: token_hash.to_owned(),
            expires_at,
            revoked_at: None,
        };
        let session = Session {
            id: row.id,
            user_id,
        };
        self.store.lock().expect("锁未中毒").push(row);
        Ok(session)
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .iter()
            .find(|r| r.token_hash == token_hash && r.revoked_at.is_none() && r.expires_at > now)
            .map(|r| Session {
                id: r.id,
                user_id: r.user_id,
            }))
    }

    async fn revoke(&self, session_id: Uuid) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        if let Some(r) = store.iter_mut().find(|r| r.id == session_id) {
            r.revoked_at.get_or_insert(OffsetDateTime::now_utc());
        }
        Ok(())
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        let now = OffsetDateTime::now_utc();
        let mut store = self.store.lock().expect("锁未中毒");
        for r in store.iter_mut() {
            if r.user_id == user_id && Some(r.id) != except && r.revoked_at.is_none() {
                r.revoked_at = Some(now);
            }
        }
        Ok(())
    }
}

/// 角色内存实现。简化:只存 (id, name) + 授予关系,不存 display_name/软删(那些 PG 才需要)。
#[derive(Default)]
pub struct InMemoryRoleRepo {
    roles: Mutex<Vec<(Uuid, String)>>,
    grants: Mutex<Vec<(Uuid, Uuid)>>, // (user_id, role_id)
}

impl InMemoryRoleRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RoleRepo for InMemoryRoleRepo {
    async fn upsert(
        &self,
        name: &str,
        _display_name: &str,
        _by: Option<String>,
    ) -> Result<Uuid, IdmError> {
        let mut roles = self.roles.lock().expect("锁未中毒");
        if let Some((id, _)) = roles.iter().find(|(_, n)| n == name) {
            return Ok(*id);
        }
        let id = Uuid::now_v7();
        roles.push((id, name.to_owned()));
        Ok(id)
    }

    async fn grant(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut grants = self.grants.lock().expect("锁未中毒");
        if !grants.contains(&(user_id, role_id)) {
            grants.push((user_id, role_id));
        }
        Ok(())
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        let grants = self.grants.lock().expect("锁未中毒");
        let roles = self.roles.lock().expect("锁未中毒");
        Ok(grants
            .iter()
            .filter(|(u, _)| *u == user_id)
            .filter_map(|(_, rid)| {
                roles
                    .iter()
                    .find(|(id, _)| id == rid)
                    .map(|(_, n)| n.clone())
            })
            .collect())
    }
}
