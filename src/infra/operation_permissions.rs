//! **API 端点 → 所需权限的唯一真相表**(文档侧)。从 `authorization` 抽出独立成文件,**一眼可定位/审计**。
//!
//! `operationId → PermissionRequirement`:`LoginOnly` = 仅登录(无特定 perm);`All` = 需全部(AND);
//! `Any` = 任一即可(OR);不在表 = public。operationId == handler 函数名(utoipa 默认回填)。
//!
//! **故意只存 operationId + perm,不存 method/path**:路由的真相是 spec(utoipa 从 `#[utoipa::path]` + nest
//! 派生),重复存会引第二个路由源、自造漂移。行为测试的 method/path 一律从 `api_spec()` 取,不从本表。
//!
//! **零漂移**:本表 + [`crate::infra::openapi::inject_operation_security`] 删掉所有手敲 `security(...)` 串 →
//! 文档侧改 Permission 必过编译期表(by construction);spec 广告的 scope ⟷ handler 实际 `require_scoped` 由
//! `tests/openapi_authz_test.rs` 行为钉死(by test)。**加端点 = 在此加一行**(漏了 → 覆盖测试 fail-closed 报红)。

use crate::kernel::authorization::Permission;

/// 端点授权要求。单权限就是 `All` 的单元素特例,不设单独变体(少一形态少一漂移面)。
#[derive(Clone, Copy, Debug)]
pub enum PermissionRequirement {
    /// 仅登录,无特定 perm → 文档 `[{"oauth2":[]}]`。
    LoginOnly,
    /// 全部要(AND)→ 文档:单 requirement 多 scope。
    All(&'static [Permission]),
    /// 任一即可(OR)→ 文档:多 requirement 各一 scope。
    Any(&'static [Permission]),
}

/// 授权表的一行:一个 operationId 要什么权限。
#[derive(Clone, Copy, Debug)]
pub struct OperationAuthorization {
    /// = handler 函数名(utoipa 默认回填的 operationId)。
    pub operation_id: &'static str,
    pub permission: PermissionRequirement,
}

/// **端点授权表**:受保护端点逐个登记;不在表 = public(`every_operation_classified` 测试兜底)。
pub const OPERATION_PERMISSIONS: &[OperationAuthorization] = &[
    OperationAuthorization {
        operation_id: "list_widgets",
        permission: PermissionRequirement::All(&[Permission::WidgetRead]),
    },
    OperationAuthorization {
        operation_id: "create_widget",
        permission: PermissionRequirement::All(&[Permission::WidgetWrite]),
    },
    OperationAuthorization {
        operation_id: "get_widget",
        permission: PermissionRequirement::All(&[Permission::WidgetRead]),
    },
    OperationAuthorization {
        operation_id: "update_widget",
        permission: PermissionRequirement::All(&[Permission::WidgetWrite]),
    },
    OperationAuthorization {
        operation_id: "delete_widget",
        permission: PermissionRequirement::All(&[Permission::WidgetDelete]),
    },
    // 仅登录(无特定 perm;数据仍限当前租户)
    OperationAuthorization {
        operation_id: "widget_stats",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "my_widget_count",
        permission: PermissionRequirement::LoginOnly,
    },
    // 后台 widget 列表:租户级读权(租户管理员可见;admin 组准入由组注入),不拿平台权限当租户数据的闸
    OperationAuthorization {
        operation_id: "admin_list_widgets",
        permission: PermissionRequirement::All(&[Permission::WidgetRead]),
    },
    // 系统监控:运维 ops:read(superadmin 独占;进程 / 依赖 / 流量的全局视图)
    OperationAuthorization {
        operation_id: "get_monitoring",
        permission: PermissionRequirement::All(&[Permission::OpsRead]),
    },
    OperationAuthorization {
        operation_id: "get_monitoring_history",
        permission: PermissionRequirement::All(&[Permission::OpsRead]),
    },
    OperationAuthorization {
        operation_id: "list_monitoring_logs",
        permission: PermissionRequirement::All(&[Permission::OpsRead]),
    },
    OperationAuthorization {
        operation_id: "widget_events",
        permission: PermissionRequirement::All(&[Permission::WidgetRead]),
    },
    // ── content:read/write/delete 三权;下载/列对象/读元数据归 read,上传/改元数据归 write ──
    OperationAuthorization {
        operation_id: "create_content",
        permission: PermissionRequirement::All(&[Permission::ContentWrite]),
    },
    OperationAuthorization {
        operation_id: "upload_content",
        permission: PermissionRequirement::All(&[Permission::ContentWrite]),
    },
    OperationAuthorization {
        operation_id: "prepare_upload",
        permission: PermissionRequirement::All(&[Permission::ContentWrite]),
    },
    OperationAuthorization {
        operation_id: "confirm_upload",
        permission: PermissionRequirement::All(&[Permission::ContentWrite]),
    },
    OperationAuthorization {
        operation_id: "list_contents",
        permission: PermissionRequirement::All(&[Permission::ContentRead]),
    },
    OperationAuthorization {
        operation_id: "get_content",
        permission: PermissionRequirement::All(&[Permission::ContentRead]),
    },
    OperationAuthorization {
        operation_id: "update_content",
        permission: PermissionRequirement::All(&[Permission::ContentWrite]),
    },
    OperationAuthorization {
        operation_id: "delete_content",
        permission: PermissionRequirement::All(&[Permission::ContentDelete]),
    },
    OperationAuthorization {
        operation_id: "download_content",
        permission: PermissionRequirement::All(&[Permission::ContentRead]),
    },
    OperationAuthorization {
        operation_id: "preview_content",
        permission: PermissionRequirement::All(&[Permission::ContentRead]),
    },
    OperationAuthorization {
        operation_id: "list_content_objects",
        permission: PermissionRequirement::All(&[Permission::ContentRead]),
    },
    OperationAuthorization {
        operation_id: "get_content_metadata",
        permission: PermissionRequirement::All(&[Permission::ContentRead]),
    },
    OperationAuthorization {
        operation_id: "set_content_metadata",
        permission: PermissionRequirement::All(&[Permission::ContentWrite]),
    },
    // ── profile:按 id 读写走 profiles:*(平台级;write:all 越权的 ownership 在 handler);本人走 /profiles/me ──
    OperationAuthorization {
        operation_id: "get_profile",
        permission: PermissionRequirement::All(&[Permission::ProfileRead]),
    },
    // 读自己:仅登录("自己"是身份事实非授权决策,对齐 get_me/my_widget_count 自我操作范式)
    OperationAuthorization {
        operation_id: "get_my_profile",
        permission: PermissionRequirement::LoginOnly,
    },
    // 改自己的资料 / 传自己的头像:同上,仅登录(资料全局一份,也不要当前租户)
    OperationAuthorization {
        operation_id: "put_my_profile",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "upload_my_avatar",
        permission: PermissionRequirement::LoginOnly,
    },
    // 有效权限查询:仅登录(问"能干什么"本身不需要先有权限)
    OperationAuthorization {
        operation_id: "get_my_permissions",
        permission: PermissionRequirement::LoginOnly,
    },
    // 改别人另要 profiles:write:all + platform:roles:那是看请求数据(路径 user_id 是不是本人)的条件闸,
    // security 表达不了 → 登记在下面的 CONDITIONAL_PERMISSIONS(文档进 x-conditional-scopes)
    OperationAuthorization {
        operation_id: "put_profile",
        permission: PermissionRequirement::All(&[Permission::ProfileWrite]),
    },
    // 头像展示端点:仅登录(头像是公开展示数据;只出被指定为头像、owner 本人的那张图)
    OperationAuthorization {
        operation_id: "get_user_avatar",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "get_me",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "update_me",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "delete_me",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "change_password",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "logout_all",
        permission: PermissionRequirement::LoginOnly,
    },
    // 租户:列我的租户 / 切换当前租户 —— 仅登录(成员关系本身就是授权依据,由 idm 校验;平台上下文也要能调)
    OperationAuthorization {
        operation_id: "list_my_tenants",
        permission: PermissionRequirement::LoginOnly,
    },
    OperationAuthorization {
        operation_id: "switch_tenant",
        permission: PermissionRequirement::LoginOnly,
    },
    // ── admin 组:组闸(admin:login 准入)在 router 层;表内 LoginOnly = 仅登录,文档的 admin:login 由组注入 ──
    OperationAuthorization {
        operation_id: "admin_get_me",
        permission: PermissionRequirement::LoginOnly,
    },
    // ── 多权限范式样板:AND(单 requirement 多 scope)/ OR(多 requirement 各一 scope)──
    OperationAuthorization {
        operation_id: "purge_preview",
        permission: PermissionRequirement::All(&[Permission::WidgetRead, Permission::WidgetDelete]),
    },
    OperationAuthorization {
        operation_id: "widget_overview",
        permission: PermissionRequirement::Any(&[Permission::WidgetRead, Permission::MembersAdmin]),
    },
    // ── users(后台账号管理):平台级 users:admin(平台管理员 + superadmin);对持平台角色的账号动手另要
    //    platform:roles —— 那是看目标数据的条件闸(handler 内),不进文档 security;admin 组准入由组注入 ──
    OperationAuthorization {
        operation_id: "list_users",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "create_user",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "get_user",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "update_user",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "delete_user",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "set_user_roles",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "reset_user_password",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "list_roles",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "get_user_profile",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "set_user_profile",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    OperationAuthorization {
        operation_id: "set_user_avatar",
        permission: PermissionRequirement::All(&[Permission::UsersAdmin]),
    },
    // ── tenants(平台租户管理):平台级 tenants:admin(平台管理员 + superadmin);admin 组准入由组注入 ──
    OperationAuthorization {
        operation_id: "list_tenants",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    OperationAuthorization {
        operation_id: "create_tenant",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    OperationAuthorization {
        operation_id: "get_tenant",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    OperationAuthorization {
        operation_id: "update_tenant",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    OperationAuthorization {
        operation_id: "list_tenant_members",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    OperationAuthorization {
        operation_id: "put_tenant_member",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    OperationAuthorization {
        operation_id: "remove_tenant_member",
        permission: PermissionRequirement::All(&[Permission::TenantsAdmin]),
    },
    // ── members(本租户成员管理):租户级 members:read / members:admin(租户 admin 持有)──
    OperationAuthorization {
        operation_id: "list_members",
        permission: PermissionRequirement::All(&[Permission::MembersRead]),
    },
    OperationAuthorization {
        operation_id: "add_member",
        permission: PermissionRequirement::All(&[Permission::MembersAdmin]),
    },
    OperationAuthorization {
        operation_id: "set_member_roles",
        permission: PermissionRequirement::All(&[Permission::MembersAdmin]),
    },
    OperationAuthorization {
        operation_id: "remove_member",
        permission: PermissionRequirement::All(&[Permission::MembersAdmin]),
    },
    // ── auth_audit(认证审计查询):audit:read(superadmin 独占)。 ──
    OperationAuthorization {
        operation_id: "list_user_auth_events",
        permission: PermissionRequirement::All(&[Permission::AuditRead]),
    },
    OperationAuthorization {
        operation_id: "list_auth_events",
        permission: PermissionRequirement::All(&[Permission::AuditRead]),
    },
    OperationAuthorization {
        operation_id: "stats_auth_events",
        permission: PermissionRequirement::All(&[Permission::AuditRead]),
    },
    OperationAuthorization {
        operation_id: "stream_auth_events",
        permission: PermissionRequirement::All(&[Permission::AuditRead]),
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
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            Self::OtherUser => "other_user",
        }
    }

    /// 文档里的人读说明(拼进 operation 的 description)。
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::OtherUser => "路径里的 user_id 不是调用者本人(改别人)时",
        }
    }
}

/// 条件权限:在 [`OPERATION_PERMISSIONS`] 的要求之外、**只在条件成立时** handler 另要的权限。
#[derive(Clone, Copy, Debug)]
pub struct ConditionalPermission {
    /// = handler 函数名(operationId)。
    pub operation_id: &'static str,
    pub when: Condition,
    /// 条件成立时另需的全部权限(AND)。
    pub permissions: &'static [Permission],
}

/// **条件权限表**(文档侧)。OpenAPI 的 security 逐 operation 静态,表达不了「改别人才要」—— 写进 security 会谎称
/// 改自己也要,不写又看不出来。所以单列在这:[`crate::infra::openapi::inject_operation_security`] 把它写进
/// operation 的 `x-conditional-scopes` 扩展(`[{when, scopes}]`)并在 description 追加一句;与 handler 的一致性由
/// `tests/openapi_authz_test.rs` 行为钉死(条件成立时逐个缺 → 403、全给 → 过;条件不成立只要 security 的)。
///
/// 只登记**看请求本身**就能判的条件。后台账号管理「目标持平台角色另要 `platform:roles`」要看目标账号的数据,
/// 不在这里表达(见上表 users 段的注释)。
pub const CONDITIONAL_PERMISSIONS: &[ConditionalPermission] = &[
    // 按 id 改别人的资料:越权的 ownership(write:all)+ 防接管(platform:roles,只有 superadmin;
    // 平台管理员改普通账号的资料走后台 PUT /admin/auth/users/{id}/profile)
    ConditionalPermission {
        operation_id: "put_profile",
        when: Condition::OtherUser,
        permissions: &[Permission::ProfileWriteAll, Permission::PlatformRoles],
    },
];

/// 按 operationId 查条件权限(可多条)。
pub fn conditional_permissions(
    id: &str,
) -> impl Iterator<Item = &'static ConditionalPermission> + '_ {
    CONDITIONAL_PERMISSIONS
        .iter()
        .filter(move |entry| entry.operation_id == id)
}

/// 按 operationId 查授权目录。不在表 = public。
#[must_use]
pub fn operation_authorization(id: &str) -> Option<&'static OperationAuthorization> {
    OPERATION_PERMISSIONS
        .iter()
        .find(|entry| entry.operation_id == id)
}
