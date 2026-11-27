//! 租户标识(多租户,spec §4.1 / §4.4)。核心侧的值类型:仓储端口签名里带 `tenant: TenantId`,
//! PG 适配器经 `infra::pg::tenant_transaction` 把它设成事务级 `app.tenant_id`(RLS 策略读它)。
//!
//! **nil UUID 永远不是合法租户**:构造只经 [`TenantId::try_new`](拒 nil)或反序列化(同一道校验),
//! 所以拿到一个 `TenantId` 就不必再判 nil。

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::app_error::AppError;

/// 默认租户(固定 UUID,slug `default`)。和 rust-idm / rust-content 的同名常量同值,
/// 各 schema 的迁移把已有数据回填到它。
pub const DEFAULT_TENANT_ID: TenantId = TenantId(Uuid::from_u128(1));

/// 租户 ID(非 nil 的 UUID)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "Uuid", into = "Uuid")]
pub struct TenantId(Uuid);

impl TenantId {
    /// 校验后构造:nil UUID → `AppError::BadRequest`(调用方入参不合法,同 content 的 nil 作用域)。
    pub fn try_new(id: Uuid) -> Result<Self, AppError> {
        if id.is_nil() {
            return Err(AppError::BadRequest("tenant_id 不能是 nil UUID".to_owned()));
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl TryFrom<Uuid> for TenantId {
    type Error = AppError;

    fn try_from(id: Uuid) -> Result<Self, Self::Error> {
        Self::try_new(id)
    }
}

impl From<TenantId> for Uuid {
    fn from(tenant: TenantId) -> Self {
        tenant.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_rejects_nil() {
        assert!(matches!(
            TenantId::try_new(Uuid::nil()),
            Err(AppError::BadRequest(_))
        ));
        assert!(TenantId::try_from(Uuid::nil()).is_err());
    }

    #[test]
    fn non_nil_roundtrips() {
        let id = Uuid::now_v7();
        let tenant = TenantId::try_new(id).unwrap();
        assert_eq!(tenant.as_uuid(), id);
        assert_eq!(Uuid::from(tenant), id);
        assert_eq!(tenant.to_string(), id.to_string());
    }

    #[test]
    fn default_tenant_is_the_fixed_uuid() {
        assert_eq!(
            DEFAULT_TENANT_ID.as_uuid().to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            TenantId::try_new(Uuid::from_u128(1)).unwrap(),
            DEFAULT_TENANT_ID
        );
    }

    #[test]
    fn serde_is_a_bare_uuid_and_rejects_nil() {
        let json = serde_json::to_string(&DEFAULT_TENANT_ID).unwrap();
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000001\"");
        let back: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DEFAULT_TENANT_ID);
        let nil = format!("\"{}\"", Uuid::nil());
        assert!(serde_json::from_str::<TenantId>(&nil).is_err());
    }
}
