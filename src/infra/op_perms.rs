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

use crate::kernel::authz::Perm;

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
    // 仅登录(无特定 perm;数据仍限当前租户)
    OpAuthz {
        operation_id: "widget_stats",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "my_widget_count",
        perm: PermReq::LoginOnly,
    },
    // 后台 widget 列表:租户级读权(租户管理员可见;admin 组准入由组注入),不拿平台权限当租户数据的闸
    OpAuthz {
        operation_id: "admin_list_widgets",
        perm: PermReq::All(&[Perm::WidgetRead]),
    },
    // 系统监控:运维 ops:read(superadmin 独占;进程 / 依赖 / 流量的全局视图)
    OpAuthz {
        operation_id: "get_monitoring",
        perm: PermReq::All(&[Perm::OpsRead]),
    },
    OpAuthz {
        operation_id: "get_monitoring_history",
        perm: PermReq::All(&[Perm::OpsRead]),
    },
    OpAuthz {
        operation_id: "list_monitoring_logs",
        perm: PermReq::All(&[Perm::OpsRead]),
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
    // ── profile:按 id 读写走 profiles:*(平台级;write:all 越权的 ownership 在 handler);本人走 /profiles/me ──
    OpAuthz {
        operation_id: "get_profile",
        perm: PermReq::All(&[Perm::ProfileRead]),
    },
    // 读自己:仅登录("自己"是身份事实非授权决策,对齐 get_me/my_widget_count 自我操作范式)
    OpAuthz {
        operation_id: "get_my_profile",
        perm: PermReq::LoginOnly,
    },
    // 改自己的资料 / 传自己的头像:同上,仅登录(资料全局一份,也不要当前租户)
    OpAuthz {
        operation_id: "put_my_profile",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "upload_my_avatar",
        perm: PermReq::LoginOnly,
    },
    // 有效权限查询:仅登录(问"能干什么"本身不需要先有权限)
    OpAuthz {
        operation_id: "get_my_permissions",
        perm: PermReq::LoginOnly,
    },
    // 改别人另要 profiles:write:all + platform:roles:那是看请求数据(路径 user_id 是不是本人)的条件闸,
    // security 表达不了 → 登记在下面的 OP_CONDITIONAL_PERMS(文档进 x-conditional-scopes)
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
    // 租户:列我的租户 / 切换当前租户 —— 仅登录(成员关系本身就是授权依据,由 idm 校验;平台上下文也要能调)
    OpAuthz {
        operation_id: "list_my_tenants",
        perm: PermReq::LoginOnly,
    },
    OpAuthz {
        operation_id: "switch_tenant",
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
        perm: PermReq::Any(&[Perm::WidgetRead, Perm::MembersAdmin]),
    },
    // ── users(后台账号管理):平台级 users:admin(平台管理员 + superadmin);对持平台角色的账号动手另要
    //    platform:roles —— 那是看目标数据的条件闸(handler 内),不进文档 security;admin 组准入由组注入 ──
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
    // ── tenants(平台租户管理):平台级 tenants:admin(平台管理员 + superadmin);admin 组准入由组注入 ──
    OpAuthz {
        operation_id: "list_tenants",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "create_tenant",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "get_tenant",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "update_tenant",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "list_tenant_members",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "put_tenant_member",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    OpAuthz {
        operation_id: "remove_tenant_member",
        perm: PermReq::All(&[Perm::TenantsAdmin]),
    },
    // ── members(本租户成员管理):租户级 members:read / members:admin(租户 admin 持有)──
    OpAuthz {
        operation_id: "list_members",
        perm: PermReq::All(&[Perm::MembersRead]),
    },
    OpAuthz {
        operation_id: "add_member",
        perm: PermReq::All(&[Perm::MembersAdmin]),
    },
    OpAuthz {
        operation_id: "set_member_roles",
        perm: PermReq::All(&[Perm::MembersAdmin]),
    },
    OpAuthz {
        operation_id: "remove_member",
        perm: PermReq::All(&[Perm::MembersAdmin]),
    },
    // ── auth_audit(认证审计查询):audit:read(superadmin 独占)。 ──
    OpAuthz {
        operation_id: "list_user_auth_events",
        perm: PermReq::All(&[Perm::AuditRead]),
    },
    OpAuthz {
        operation_id: "list_auth_events",
        perm: PermReq::All(&[Perm::AuditRead]),
    },
    OpAuthz {
        operation_id: "stats_auth_events",
        perm: PermReq::All(&[Perm::AuditRead]),
    },
    OpAuthz {
        operation_id: "stream_auth_events",
        perm: PermReq::All(&[Perm::AuditRead]),
    },
];

/// 条件权限的触发条件(闭集)。每加一种,`tests/openapi_authz_test.rs` 的
/// `conditional_scopes_documented_and_enforced` 要补对应的探测(不认识的条件那里直接报红)。
#[derive(Clone, Copy, Debug)]
pub enum Condition {
    /// 路径里的 `{user_id}` 不是调用者本人(改别人的资源)。
    OtherUser,
}

impl Condition {
    /// 文档里的机读值(`x-conditional-scopes[].when`)。
    pub fn wire(self) -> &'static str {
        match self {
            Self::OtherUser => "other_user",
        }
    }

    /// 文档里的人读说明(拼进 operation 的 description)。
    pub fn describe(self) -> &'static str {
        match self {
            Self::OtherUser => "路径里的 user_id 不是调用者本人(改别人)时",
        }
    }
}

/// 条件权限:在 [`OP_PERMS`] 的要求之外、**只在条件成立时** handler 另要的权限。
#[derive(Clone, Copy, Debug)]
pub struct OpConditional {
    pub operation_id: &'static str,
    pub when: Condition,
    /// 条件成立时另需的全部权限(AND)。
    pub perms: &'static [Perm],
}

/// **条件权限表**(文档侧)。OpenAPI 的 security 逐 operation 静态,表达不了「改别人才要」—— 写进 security 会谎称
/// 改自己也要,不写又看不出来。所以单列在这:[`crate::infra::openapi::inject_operation_security`] 把它写进
/// operation 的 `x-conditional-scopes` 扩展(`[{when, scopes}]`)并在 description 追加一句;与 handler 的一致性由
/// `tests/openapi_authz_test.rs` 行为钉死(条件成立时逐个缺 → 403、全给 → 过;条件不成立只要 security 的)。
///
/// 只登记**看请求本身**就能判的条件。后台账号管理「目标持平台角色另要 `platform:roles`」要看目标账号的数据,
/// 不在这里表达(见上表 users 段的注释)。
pub const OP_CONDITIONAL_PERMS: &[OpConditional] = &[
    // 按 id 改别人的资料:越权的 ownership(write:all)+ 防接管(platform:roles,只有 superadmin;
    // 平台管理员改普通账号的资料走后台 PUT /admin/auth/users/{id}/profile)
    OpConditional {
        operation_id: "put_profile",
        when: Condition::OtherUser,
        perms: &[Perm::ProfileWriteAll, Perm::PlatformRoles],
    },
];

/// 按 operationId 查条件权限(可多条)。
pub fn op_conditional(id: &str) -> impl Iterator<Item = &'static OpConditional> + '_ {
    OP_CONDITIONAL_PERMS
        .iter()
        .filter(move |o| o.operation_id == id)
}

/// 按 operationId 查授权目录。不在表 = public。
pub fn op_authz(id: &str) -> Option<&'static OpAuthz> {
    OP_PERMS.iter().find(|o| o.operation_id == id)
}
