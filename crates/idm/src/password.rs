//! 密码哈希端口(可拔插)。Go 的 interface,在 Rust 里是 **trait + `Arc<dyn>`**(与 repo 同范式)。
//!
//! 解耦的理由是**具体需求**,不是"argon2 是外部库":
//! ① 测试躲开 argon2 的 ~100ms(否则每个 register/login 用例都拖慢);② 实现可换。
//! 注:**换算法**主要靠 PHC 串自描述(verify 按串前缀选算法),trait 管的是"换实现 / 测试替身"。

use crate::error::IdmError;

/// 密码哈希端口。命名刻意避开 `argon2::password_hash::PasswordHasher`(RustCrypto 的 trait)以防撞名。
pub trait PwHasher: Send + Sync {
    /// 明文 → PHC 串(自带算法标识 + 盐 + 参数)。
    fn hash(&self, plain: &str) -> Result<String, IdmError>;
    /// 校验明文 vs PHC 串。串自描述算法 → 天然支持多算法共存(迁移)。
    fn verify(&self, plain: &str, phc: &str) -> Result<bool, IdmError>;
}

/// 生产实现:argon2id(默认参数)。
/// **CPU 密集(~100ms)**:在 async handler 里调用务必 `tokio::task::spawn_blocking` 包起来,
/// 否则阻塞 tokio worker 线程、饿死其它请求。
pub struct Argon2Hasher;

impl PwHasher for Argon2Hasher {
    fn hash(&self, plain: &str) -> Result<String, IdmError> {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        use argon2::Argon2;
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(plain.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("argon2 hash 失败: {e}")))
    }

    fn verify(&self, plain: &str, phc: &str) -> Result<bool, IdmError> {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        use argon2::Argon2;
        // PHC 解析失败 = 库里存了坏串 → Internal(原始措辞进日志);密码不匹配 → Ok(false)。
        let parsed = PasswordHash::new(phc)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("PHC 串解析失败: {e}")))?;
        Ok(Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok())
    }
}

/// 测试实现:前缀标记 + 明文比对,不做真哈希 → 躲开 argon2 的 ~100ms。
///
/// 故意**不**加 `#[cfg(test)]`:集成测试(`tests/`)是独立 crate,需要能从外部构造它注入 `IdmState`。
/// 仅供测试装配使用,生产装配永远注入 `Argon2Hasher`。
pub struct FakeHasher;

const FAKE_PREFIX: &str = "fake$";

impl PwHasher for FakeHasher {
    fn hash(&self, plain: &str) -> Result<String, IdmError> {
        Ok(format!("{FAKE_PREFIX}{plain}"))
    }
    fn verify(&self, plain: &str, phc: &str) -> Result<bool, IdmError> {
        Ok(phc == format!("{FAKE_PREFIX}{plain}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_round_trip_and_phc_self_describes() {
        let h = Argon2Hasher;
        let phc = h.hash("hunter42").unwrap();
        // PHC 串自描述:前缀即算法标识(迁移/验证靠它,不靠 trait)
        assert!(phc.starts_with("$argon2id$"), "应是 argon2id PHC 串: {phc}");
        assert!(h.verify("hunter42", &phc).unwrap());
        assert!(!h.verify("wrong", &phc).unwrap());
    }

    #[test]
    fn fake_round_trip_is_fast_and_correct() {
        let h = FakeHasher;
        let phc = h.hash("pw").unwrap();
        assert!(h.verify("pw", &phc).unwrap());
        assert!(!h.verify("nope", &phc).unwrap());
    }

    /// 端口可拔插:两个实现都满足同一 trait,可经 `Arc<dyn PwHasher>` 互换注入。
    #[test]
    fn both_satisfy_the_port() {
        let impls: Vec<std::sync::Arc<dyn PwHasher>> = vec![
            std::sync::Arc::new(Argon2Hasher),
            std::sync::Arc::new(FakeHasher),
        ];
        for h in impls {
            let phc = h.hash("secret-pw").unwrap();
            assert!(h.verify("secret-pw", &phc).unwrap());
            assert!(!h.verify("other", &phc).unwrap());
        }
    }
}
