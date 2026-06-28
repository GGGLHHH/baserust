//! idm 仓储内存实现 —— 脚手架默认,无 DB 即可跑通注册/登录全链路 + 写单测。
//! 镜像 PG 的软删过滤、username 唯一、email(有则)唯一,保 parity。

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Session, SessionRepo, User, UserRepo, UserWithHash};
use crate::infra::error::AppError;

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
    ) -> Result<User, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // username 唯一 + email(有则)唯一,仅对存活行:镜像两个 partial unique 索引。
        let dup = store.values().any(|r| {
            r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(AppError::Conflict("用户名或邮箱已被占用".to_owned()));
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

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, AppError> {
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

    async fn find_by_id(&self, id: Uuid) -> Result<User, AppError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .ok_or(AppError::NotFound)
    }
}

/// 会话内存行。token_hash/expires_at/revoked_at 暂存待 refresh/logout 块读取。
#[derive(Clone)]
#[allow(dead_code)]
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
    ) -> Result<Session, AppError> {
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
}
