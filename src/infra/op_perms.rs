//! **API 端点 → 所需权限的唯一真相表**(文档侧)。从 `authz` 抽出独立成文件,**一眼可定位/审计**。
//!
//! `operationId → Option<Perm>`:`Some(p)` = 需该 perm;`None` = 仅登录(无特定 perm);不在表 = public。
//! operationId == handler 函数名(utoipa 默认回填)。
//!
//! **故意只存 operationId + perm,不存 method/path**:路由的真相是 spec(utoipa 从 `#[utoipa::path]` + nest
//! 派生),重复存会引第二个路由源、自造漂移。行为测试的 method/path 一律从 `api_spec()` 取,不从本表。
//!
//! **零漂移**:本表 + [`crate::infra::openapi::inject_operation_security`] 删掉所有手敲 `security(...)` 串 →
//! 文档侧改 Perm 必过编译期表(by construction);spec 广告的 scope ⟷ handler 实际 `require_scoped` 由
//! `tests/openapi_authz_test.rs` 行为钉死(by test)。**加端点 = 在此加一行**(漏了 → 覆盖测试 fail-closed 报红)。

use crate::infra::authz::Perm;

#[derive(Clone, Copy, Debug)]
pub struct OpAuthz {
    pub operation_id: &'static str,
    pub perm: Option<Perm>,
}

pub const OP_PERMS: &[OpAuthz] = &[
    OpAuthz {
        operation_id: "list_widgets",
        perm: Some(Perm::WidgetRead),
    },
    OpAuthz {
        operation_id: "create_widget",
        perm: Some(Perm::WidgetWrite),
    },
    OpAuthz {
        operation_id: "get_widget",
        perm: Some(Perm::WidgetRead),
    },
    OpAuthz {
        operation_id: "update_widget",
        perm: Some(Perm::WidgetWrite),
    },
    OpAuthz {
        operation_id: "delete_widget",
        perm: Some(Perm::WidgetDelete),
    },
    // 仅登录(无特定 perm);widget_stats 是 public → 不在表
    OpAuthz {
        operation_id: "my_widget_count",
        perm: None,
    },
    // superadmin-only:gate 一个只 superadmin 持有的 perm(users:admin)
    OpAuthz {
        operation_id: "admin_list_widgets",
        perm: Some(Perm::UsersAdmin),
    },
    OpAuthz {
        operation_id: "get_me",
        perm: None,
    },
    OpAuthz {
        operation_id: "update_me",
        perm: None,
    },
    OpAuthz {
        operation_id: "delete_me",
        perm: None,
    },
    OpAuthz {
        operation_id: "change_password",
        perm: None,
    },
    OpAuthz {
        operation_id: "logout_all",
        perm: None,
    },
];

/// 按 operationId 查授权目录。不在表 = public。
pub fn op_authz(id: &str) -> Option<&'static OpAuthz> {
    OP_PERMS.iter().find(|o| o.operation_id == id)
}
