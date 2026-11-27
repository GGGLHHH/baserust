//! seed 跳过补授那条日志的**级别**:声明的 superadmin 被跳过、库里 0 个 superadmin → ERROR(要人去看容器日志);
//! 其余仍是 WARN。
//!
//! 单独一个测试二进制、装**全局** subscriber:tracing 的 callsite interest 是进程级缓存,和并行跑的别的测试共用时,
//! 线程局部的 `set_default` 会偶发漏采(同一个 callsite 先在没 subscriber 的线程上注册就被缓存成「不要」)。

use idm::NewUser;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::{subscriber, Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

use baserust::app::seed::{apply, IdmSeedRepos, SeedData};
use idm::{
    FakeHasher, InMemoryMemberRepo, InMemoryRoleRepo, InMemoryTenantRepo, InMemoryUserRepo,
    UserRepo,
};

/// 采到的一条日志事件。
struct CapturedEvent {
    level: Level,
    /// 格式化后的 `message` 字段。
    message: String,
}

/// 把每条日志事件记进共享列表的 subscriber 层。
#[derive(Clone, Default)]
struct LogGrab(Arc<Mutex<Vec<CapturedEvent>>>);

impl<S: Subscriber> Layer<S> for LogGrab {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        /// 只取 `message` 字段的访问器。
        struct MessageVisitor(String);
        impl Visit for MessageVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(CapturedEvent {
            level: *event.metadata().level(),
            message: visitor.0,
        });
    }
}

impl LogGrab {
    /// 消息含 `needle` 的事件的级别。
    fn levels_of(&self, needle: &str) -> Vec<Level> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|captured| captured.message.contains(needle))
            .map(|captured| captured.level)
            .collect()
    }
}

fn parse(text: &str) -> SeedData {
    toml::from_str(text).unwrap()
}

#[tokio::test]
async fn skip_log_is_error_only_when_no_superadmin_left() {
    let grab = LogGrab::default();
    subscriber::set_global_default(tracing_subscriber::registry().with(grab.clone())).unwrap();

    let users = InMemoryUserRepo::new();
    let roles = InMemoryRoleRepo::new_shared_with(&users);
    let tenants = InMemoryTenantRepo::new_shared_with(&users);
    let members = InMemoryMemberRepo::new_shared_with(&users);
    let repos = IdmSeedRepos {
        users: &users,
        roles: &roles,
        tenants: &tenants,
        members: &members,
    };
    // 空库上有人先注册了 seed 里的用户名(密码不是 seed 里的)→ seed 确认不了、跳过补授
    for name in ["root", "ops"] {
        users
            .create_with_roles(
                NewUser {
                    username: name,
                    email: None,
                    password_hash: "fake$attacker",
                },
                &[],
                None,
            )
            .await
            .unwrap();
    }
    let root = apply(
        repos,
        &FakeHasher,
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
        &FakeHasher,
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
        vec![Level::ERROR],
        "声明的 superadmin 被跳过、库里 0 个 superadmin → ERROR"
    );
    assert_eq!(
        grab.levels_of("seed 声明的账号 ops 已存在"),
        vec![Level::WARN],
        "非 superadmin → 仍是 WARN"
    );
}
