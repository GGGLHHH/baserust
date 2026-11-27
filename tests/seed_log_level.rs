//! seed 跳过补授那条日志的**级别**:声明的 superadmin 被跳过、库里 0 个 superadmin → ERROR(要人去看容器日志);
//! 其余仍是 WARN。
//!
//! 单独一个测试二进制、装**全局** subscriber:tracing 的 callsite interest 是进程级缓存,和并行跑的别的测试共用时,
//! 线程局部的 `set_default` 会偶发漏采(同一个 callsite 先在没 subscriber 的线程上注册就被缓存成「不要」)。

use std::sync::{Arc, Mutex};

use baserust::app::seed::{apply, IdmSeedRepos, SeedData};
use idm::{InMemoryMemberRepo, InMemoryRoleRepo, InMemoryTenantRepo, InMemoryUserRepo, UserRepo};
use tracing_subscriber::layer::SubscriberExt;

/// 记下每条事件的 (级别, 格式化后的消息)。
#[derive(Clone, Default)]
struct LogGrab(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogGrab {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Msg(String);
        impl tracing::field::Visit for Msg {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                if f.name() == "message" {
                    self.0 = format!("{v:?}");
                }
            }
        }
        let mut m = Msg(String::new());
        event.record(&mut m);
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), m.0));
    }
}

impl LogGrab {
    /// 消息含 `needle` 的事件的级别。
    fn levels_of(&self, needle: &str) -> Vec<tracing::Level> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m)| m.contains(needle))
            .map(|(l, _)| *l)
            .collect()
    }
}

fn parse(s: &str) -> SeedData {
    toml::from_str(s).unwrap()
}

#[tokio::test]
async fn skip_log_is_error_only_when_no_superadmin_left() {
    let grab = LogGrab::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(grab.clone()))
        .unwrap();

    let users = InMemoryUserRepo::new();
    let roles = InMemoryRoleRepo::sharing_with(&users);
    let tenants = InMemoryTenantRepo::sharing_with(&users);
    let members = InMemoryMemberRepo::sharing_with(&users);
    let repos = IdmSeedRepos {
        users: &users,
        roles: &roles,
        tenants: &tenants,
        members: &members,
    };
    // 空库上有人先注册了 seed 里的用户名(密码不是 seed 里的)→ seed 确认不了、跳过补授
    for name in ["root", "ops"] {
        users
            .create_with_roles(name, None, "fake$attacker", &[], None)
            .await
            .unwrap();
    }
    let root = apply(
        repos,
        &idm::FakeHasher,
        &parse(
            r#"[[users]]
username = "root"
password = "p"
platform_roles = ["superadmin"]"#,
        ),
        None,
    )
    .await
    .unwrap();
    assert_eq!(root.skipped.len(), 1);
    let ops = apply(
        repos,
        &idm::FakeHasher,
        &parse(
            r#"[[users]]
username = "ops"
password = "p"
platform_roles = ["platform_admin"]"#,
        ),
        None,
    )
    .await
    .unwrap();
    assert_eq!(ops.skipped.len(), 1);

    assert_eq!(
        grab.levels_of("seed 声明的账号 root 已存在"),
        vec![tracing::Level::ERROR],
        "声明的 superadmin 被跳过、库里 0 个 superadmin → ERROR"
    );
    assert_eq!(
        grab.levels_of("seed 声明的账号 ops 已存在"),
        vec![tracing::Level::WARN],
        "非 superadmin → 仍是 WARN"
    );
}
