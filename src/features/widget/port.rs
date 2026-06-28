//! widget 的**跨模块需求端口**:富化要从别的模块按 id 批量取用户展示信息。
//! 端口归**消费方**(widget 只声明"我要什么",不 import idm);实现/适配在 app 组合根(app/adapters/)。
//! 这是 ports-and-adapters 的 port 一侧:`widget/port.rs` + `app/adapters/` 连起来就是该架构本身。

use std::collections::HashMap;

use async_trait::async_trait;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::infra::error::AppError;

/// 富化用的用户瘦快照 —— **只含 widget 展示要的字段**,不是 idm.User 全貌(窄接口)。
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct UserBrief {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
}

/// widget 富化所需的用户目录端口:**一次**按 id 批量解析,防 N+1。
/// 实现见 app/adapters(InProcess 进程内 / 将来 Http 分进程)。
#[async_trait]
pub trait UserDirectory: Send + Sync {
    /// 批量解析 id→brief;查不到的 id **不在** map 里(交调用方降级)。
    async fn batch_by_ids(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, UserBrief>, AppError>;
}

/// 静态实现:用预置 map 回答 —— 脚手架测试 + 业务方测富化用(无需真连 idm)。
/// `empty()` 总返回空,可作"无富化源"占位(created_by_user 全 null)。
pub struct StaticUserDirectory(pub HashMap<Uuid, UserBrief>);

impl StaticUserDirectory {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait]
impl UserDirectory for StaticUserDirectory {
    async fn batch_by_ids(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, UserBrief>, AppError> {
        Ok(ids
            .iter()
            .filter_map(|id| self.0.get(id).map(|b| (*id, b.clone())))
            .collect())
    }
}
