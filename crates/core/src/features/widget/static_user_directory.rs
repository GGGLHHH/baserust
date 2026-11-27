//! widget 用户目录端口的**静态实现**(测试替身 / 无富化源占位)。纯 Rust。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::widget::ports::{UserBrief, UserDirectory};
use crate::kernel::app_error::AppError;

/// 静态实现:用预置 map 回答 —— 脚手架测试 + 业务方测富化用(无需真连 idm)。
/// `new()` 总返回空,可作"无富化源"占位(created_by_user 全 null)。
#[derive(Default)]
pub struct StaticUserDirectory(pub HashMap<Uuid, UserBrief>);

impl StaticUserDirectory {
    /// 空目录(什么都查不到)。
    #[must_use]
    pub fn new() -> Self {
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
