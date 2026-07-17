//! **API 端点 → 所需权限的唯一真相表**(文档侧)。从 `authz` 抽出独立成文件,**一眼可定位/审计**。
//!
//! `operationId → PermReq`:`LoginOnly` = 仅登录(无特定 perm);`All` = 需全部(AND);
//! `Any` = 任一即可(OR);不在表 = public。operationId == handler 函数名(utoipa 默认回填)。
//!
//! **故意只存 operationId + perm,不存 method/path**:路由的真相是 spec(utoipa 从 `#[utoipa::path]` + nest
//! 派生),重复存会引第二个路由源、自造漂移。行为测试的 method/path 一律从 `api_spec()` 取,不从本表。
//!
//! **零漂移**:本表 + [`crate::infra::openapi::inject_operation_security`] 删掉所有手敲 `security(...)` 串 →
//! 文档侧改 Perm 必过编译期表(by construction);spec 广告的 scope ⟷ handler 实际 `require_scoped` 由
//! `tests/openapi_authz_test.rs` 行为钉死(by test)。**加端点 = 在此加一行**(漏了 → 覆盖测试 fail-closed 报红)。

use crate::infra::authz::Perm;

/// 端点授权要求。单权限就是 `All` 的单元素特例,不设单独变体(少一形态少一漂移面)。
#[derive(Clone, Copy, Debug)]
pub enum PermReq {
    /// 仅登录,无特定 perm → 文档 `[{"oauth2":[]}]`。
    LoginOnly,
    /// 全部要(AND)→ 文档:单 requirement 多 scope。
    All(&'static [Perm]),
    /// 任一即可(OR)→ 文档:多 requirement 各一 scope。
    Any(&'static [Perm]),
}

#[derive(Clone, Copy, Debug)]
pub struct OpAuthz {
    pub operation_id: &'static str,
    pub perm: PermReq,
}

pub const OP_PERMS: &[OpAuthz] = &[
    OpAuthz {
        operation_id: "list_widgets",
        perm: PermReq::All(&[Perm::WidgetRead]),
    },
    OpAuthz {
        operation_id: "create_widget",
        perm: PermReq::All(&[Perm::WidgetWrite]),
    },
    OpAuthz {
        operation_id: "get_widget",
        perm: PermReq::All(&[Perm::WidgetRead]),
    },
    OpAuthz {
        operation_id: "update_widget",
        perm: PermReq::All(&[Perm::WidgetWrite]),
    },
    OpAuthz {
        operation_id: "delete_widget",
        perm: PermReq::All(&[Perm::WidgetDelete]),
    },
    // 仅登录(无特定 perm)
    OpAuthz {
        operation_id: "my_widget_count",
        perm: PermReq::LoginOnly,
    },
    // widget_stats 曾是 public(不在本表)。上租户轴后挪进 frontend 组 —— public 端点没有
    // token 就造不出 TenantId(spec §6.1)。仅登录:计数不需要特定 perm,租户闸已在 handler。
    OpAuthz {
        operation_id: "widget_stats",
        perm: PermReq::LoginOnly,
    },
    // 租户切换(spec §4.9):**仅登录,不设专门的 perm** —— 授权靠成员资格本身,
    // 不是靠角色:能不能列出/切进某租户,取决于你是不是它的成员(`TenantRepo::membership`),
    // 而那是数据事实、不是 RBAC 判定。给它发一个 `tenants:switch` 之类的 perm 反而会造出
    // 「有 perm 但不是成员」的荒谬状态。非成员 → 404(不是 403,不泄露该租户存在)。
    OpAuthz {
        operation_id: "list_my_tenants",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "put_active_tenant",
        perm: PermReq::LoginOnly,
    },
    // superadmin-only:gate 一个只 superadmin 持有的 perm(users:admin)
    OpAuthz {
        operation_id: "admin_list_widgets",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "widget_events",
        perm: PermReq::All(&[Perm::WidgetRead]),
    },
    // ── content:read/write/delete 三权;下载/列对象/读元数据归 read,上传/改元数据归 write ──
    OpAuthz {
        operation_id: "create_content",
        perm: PermReq::All(&[Perm::ContentWrite]),
    },
    OpAuthz {
        operation_id: "upload_content",
        perm: PermReq::All(&[Perm::ContentWrite]),
    },
    OpAuthz {
        operation_id: "prepare_upload",
        perm: PermReq::All(&[Perm::ContentWrite]),
    },
    OpAuthz {
        operation_id: "confirm_upload",
        perm: PermReq::All(&[Perm::ContentWrite]),
    },
    OpAuthz {
        operation_id: "list_contents",
        perm: PermReq::All(&[Perm::ContentRead]),
    },
    OpAuthz {
        operation_id: "get_content",
        perm: PermReq::All(&[Perm::ContentRead]),
    },
    OpAuthz {
        operation_id: "update_content",
        perm: PermReq::All(&[Perm::ContentWrite]),
    },
    OpAuthz {
        operation_id: "delete_content",
        perm: PermReq::All(&[Perm::ContentDelete]),
    },
    OpAuthz {
        operation_id: "download_content",
        perm: PermReq::All(&[Perm::ContentRead]),
    },
    OpAuthz {
        operation_id: "preview_content",
        perm: PermReq::All(&[Perm::ContentRead]),
    },
    OpAuthz {
        operation_id: "list_content_objects",
        perm: PermReq::All(&[Perm::ContentRead]),
    },
    OpAuthz {
        operation_id: "get_content_metadata",
        perm: PermReq::All(&[Perm::ContentRead]),
    },
    OpAuthz {
        operation_id: "set_content_metadata",
        perm: PermReq::All(&[Perm::ContentWrite]),
    },
    // ── profile:任意登录可读(read);写走 write(write:all 越权的 ownership 在 handler)──
    OpAuthz {
        operation_id: "get_profile",
        perm: PermReq::All(&[Perm::ProfileRead]),
    },
    // 读自己:仅登录("自己"是身份事实非授权决策,对齐 get_me/my_widget_count 自我操作范式)
    OpAuthz {
        operation_id: "get_my_profile",
        perm: PermReq::LoginOnly,
    },
    // 有效权限查询:仅登录(问"能干什么"本身不需要先有权限)
    OpAuthz {
        operation_id: "get_my_permissions",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "put_profile",
        perm: PermReq::All(&[Perm::ProfileWrite]),
    },
    // 头像展示端点:仅登录(头像是公开展示数据;只出被指定为头像、owner 本人的那张图)
    OpAuthz {
        operation_id: "get_user_avatar",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "get_me",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "update_me",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "delete_me",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "change_password",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "logout_all",
        perm: PermReq::LoginOnly,
    },
    // ── admin 组:组闸(admin:login 准入)在 router 层;表内 LoginOnly = 仅登录,文档的 admin:login 由组注入 ──
    OpAuthz {
        operation_id: "admin_get_me",
        perm: PermReq::LoginOnly,
    },
    // ── 多权限范式样板:AND(单 requirement 多 scope)/ OR(多 requirement 各一 scope)──
    OpAuthz {
        operation_id: "purge_preview",
        perm: PermReq::All(&[Perm::WidgetRead, Perm::WidgetDelete]),
    },
    OpAuthz {
        operation_id: "widget_overview",
        perm: PermReq::Any(&[Perm::WidgetRead, Perm::UsersAdmin]),
    },
    // ── users(后台用户管理):全 superadmin 专属(users:admin);admin:login 由 admin 组注入 ──
    OpAuthz {
        operation_id: "list_users",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "create_user",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "get_user",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "update_user",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "delete_user",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "set_user_roles",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "reset_user_password",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "list_roles",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "get_user_profile",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "set_user_profile",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "set_user_avatar",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    // ── auth_audit(认证审计查询):同 users,superadmin 专属(users:admin)。 ──
    OpAuthz {
        operation_id: "list_user_auth_events",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "list_auth_events",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    OpAuthz {
        operation_id: "stats_auth_events",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
    // ── 租户管理(P6)──
    // 平台开通(admin/auth/tenants):superadmin 专属 tenants:admin。
    OpAuthz {
        operation_id: "create_tenant",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "list_tenants",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "update_tenant",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    // 自助成员管理(frontend/auth/tenants/members):**仅登录**,授权靠 handler 里的活 tn:admin
    // 检查(tenant_members.role 数据事实,同切换端点 —— 不给 perm 免得造「有 perm 但不是本租户
    // admin」的荒谬状态)。非本租户 admin → 403。
    OpAuthz {
        operation_id: "list_members",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "add_member",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "remove_member",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "stream_auth_events",
        perm: PermReq::All(&[Perm::UsersAdmin]),
    },
];

/// 按 operationId 查授权目录。不在表 = public。
pub fn op_authz(id: &str) -> Option<&'static OpAuthz> {
    OP_PERMS.iter().find(|o| o.operation_id == id)
}
