//! 授权的 **HTTP 适配**:token scope 提取器、组闸中间件(`require_login` / `require_admin_login`)、
//! `GET /permissions/me` 端点,以及 `Permission` / `RoleName` 的 OpenAPI schema。
//! 词表与判定(`Permission` / `RoleName` / `Policy` / `Access`)是核心,在 `kernel::authorization`。

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use idm::AuthUser;
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::app::app_state::AppState;
use crate::infra::http::audit::CurrentUser;
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::Json;
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::{Permission, Policy, RoleName};

// schema 名 `Perm` 是已发布的 OpenAPI 契约(前端生成类型名),Rust 侧改名为 `Permission`
// 后线上名字保持不变。
crate::closed_enum_to_schema!(
    PermissionSchema => Permission as "Perm",
    Permission::ALL,
    "权限词表的**唯一真相**(封闭集)。handler 用变体 `Permission::WidgetWrite`,拼错=编译错。\nwire 串(TOML / JWT scope)经 `rename` 映射;未知串 → 反序列化失败 → 启动期挡住(fail-fast)。\n加权限 = 加一个变体 + `rename`,别处不动。"
);
crate::closed_enum_to_schema!(
    RoleNameSchema => RoleName,
    RoleName::ALL,
    "角色名的**唯一真相**(封闭集)。角色本身不做动态 CRUD(角色**有哪些权限**才可运行时改,\n见 `role_permissions` 表);故角色集编进代码。wire 串经 `rename`,与 idm.roles.name / JWT\nclaim / `role_permissions.role_name` 同源。加角色 = 加变体 + 补 `ALL`/`display_name`/`scope`/`default_permissions`。"
);

/// 当前请求令牌的**当前租户**(鉴权中间件验过 token 后塞进 extensions;平台上下文没有)。
/// `id` 与 `AuthUser.tenant_id` 同值;`slug` / `name` 只作展示(`GET /permissions/me`),
/// 降权令牌 / 旧 token 没有它们。授权一律看 `AuthUser` + [`crate::infra::http::audit::CurrentTenant`]。
#[derive(Clone, Debug)]
pub struct TokenTenant {
    pub id: Uuid,
    pub slug: Option<String>,
    pub name: Option<String>,
}

/// 当前请求令牌携带的 scope(per-token 权限子集)。鉴权中间件验过 token 后塞进 extensions;
/// **空 = 无 scope 限制**(第一方满权令牌)。非空 = 降权令牌,有效权限再 ∩ 它。
///
/// extractor:只读 extension,无则空(未认证由 `CurrentUser` 先 401 挡掉,这里不重复判)。
#[derive(Clone, Debug, Default)]
pub struct TokenScope(pub Vec<Permission>);

impl<S: Send + Sync> FromRequestParts<S> for TokenScope {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<TokenScope>()
            .cloned()
            .unwrap_or_default())
    }
}

/// 组闸:需登录(`/api/v1/frontend` 组)。粗过滤:extensions 无 `AuthUser`(`auth::authenticate`
/// 没验出人)→ 401 统一 `ErrorBody`。细粒度(perm/scope/ownership)仍归端点内三轴 ——
/// 本闸只是防御纵深第一层。注:axum `.layer()` 只包已注册路由,组内未知路径仍走 fallback 404、不过闸。
pub async fn require_login(request: Request, next: Next) -> Response {
    if request.extensions().get::<AuthUser>().is_none() {
        return ApiError::from(AppError::Unauthorized).into_response();
    }
    next.run(request).await
}

/// 组闸:登录 + **后台准入**(`/api/v1/admin` 组):当前租户里的 `admin:login`,或任一平台级权限
/// (平台管理员不必属于任何租户),见 [`Policy::require_admin_entry`]。**走 `require_scoped`(role ∩ scope)**,
/// 与端点内闸、openapi_authz 探针同一评估语义 —— 降权令牌(scope 未含任一准入权限)即便 role 够也挡。
/// 闸的是**准入**(租户 admin + 平台管理员皆过);组内平台能力端点再各自 gate 平台级权限(账号 `users:admin`、监控 `ops:read`、审计 `audit:read`…)。
/// state 直接吃 `Arc<Policy>`(infra 不 import app 的 AppState,守分层)。
pub async fn require_admin_login(
    State(policy): State<Arc<Policy>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(user) = request.extensions().get::<AuthUser>().cloned() else {
        return ApiError::from(AppError::Unauthorized).into_response();
    };
    let scope = request
        .extensions()
        .get::<TokenScope>()
        .cloned()
        .unwrap_or_default();
    if let Err(error) = policy.require_admin_entry(&user, &scope.0) {
        return ApiError::from(error).into_response();
    }
    next.run(request).await
}

// ── 端点:当前令牌的有效权限。"能干什么"归 app(authz 拥有此概念,端点就住这;
//    infra 引 AppState 有 openapi::doc_routes 先例)。idm 的 /auth/me 只给身份事实,不回答权限
//    —— idm 进程的 policy 是 seed 嵌入副本,PG 模式下与 app 会漂,放那边文档会说谎。 ──

/// 当前租户的展示信息(`GET /permissions/me` 的 `tenant`)。
#[derive(Serialize, utoipa::ToSchema)]
pub struct CurrentTenantView {
    pub id: Uuid,
    /// 来自登录 / 切换时签进 token 的值;降权令牌没有 → 空串。
    pub slug: String,
    /// 同上(租户改名后,到 token 过期 / refresh 前仍是旧名)。
    pub name: String,
}

/// `GET /permissions/me` 响应。`roles` 来自 token claim;`permissions` 是**有效**集:
/// (平台角色给的平台级 ∪ 当前租户角色给的租户级,含 implies)∩ scope 收窄,wire 串排序输出。
#[derive(Serialize, utoipa::ToSchema)]
pub struct MyPermissionsResponse {
    /// token claim 里的**平台角色**名(闭集,生成前端 union)。
    #[schema(value_type = Vec<RoleNameSchema>)]
    pub roles: Vec<RoleName>,
    /// 当前租户内的角色名(平台上下文 → 空)。
    #[schema(value_type = Vec<RoleNameSchema>)]
    pub tenant_roles: Vec<RoleName>,
    /// 当前租户;平台上下文(没加入任何组织 / 平台管理员)→ `null`。
    pub tenant: Option<CurrentTenantView>,
    /// 有效权限(闭集,wire 串序输出)。前端按钮显隐 / codegen accessPolicies `has()` 的数据源。
    #[schema(value_type = Vec<PermissionSchema>)]
    pub permissions: Vec<Permission>,
}

/// 当前令牌能干什么(仅登录零 perm —— 自我操作范式;问"能干什么"本身不需要先有权限)。
/// 逐 perm 走 [`Policy::require_scoped`] 过滤:与所有闸同一评估路径,零漂移;
/// 降权令牌得到 scope 收窄后的真实集。
#[utoipa::path(
    get,
    path = "/permissions/me",
    tag = "me",
    responses(
        (status = 200, description = "当前令牌的角色、当前租户与有效权限(role ∩ scope,排序)", body = MyPermissionsResponse),
        (status = 401, description = "未认证", body = ErrorBody)
    )
)]
pub async fn get_my_permissions(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    scope: TokenScope,
    token_tenant: Option<Extension<TokenTenant>>,
) -> Json<MyPermissionsResponse> {
    let mut permissions: Vec<Permission> = state
        .policy
        .permissions_of(&user)
        .into_iter()
        .filter(|&permission| {
            state
                .policy
                .require_scoped(&user, &scope.0, permission)
                .is_ok()
        })
        .collect();
    permissions.sort_by_key(|permission| permission.wire()); // 仍按 wire 串序,JSON 输出不变

    // 下面只剩移走字段的读法:直接拆开 user,不必再 clone 角色列表。
    let AuthUser {
        roles,
        tenant_id,
        tenant_roles,
        ..
    } = user;
    let roles = RoleName::parse_lossy(roles);
    // 租户只认 AuthUser.tenant_id(授权口径);TokenTenant 只补展示用的 slug / 名称。
    let tenant = tenant_id.map(|id| {
        let info = token_tenant
            .as_ref()
            .map(|extension| &extension.0)
            .filter(|info| info.id == id);
        CurrentTenantView {
            id,
            slug: info.and_then(|info| info.slug.clone()).unwrap_or_default(),
            name: info.and_then(|info| info.name.clone()).unwrap_or_default(),
        }
    });
    let tenant_roles = if tenant.is_some() {
        RoleName::parse_lossy(tenant_roles)
    } else {
        Vec::new()
    };
    Json(MyPermissionsResponse {
        roles,
        tenant_roles,
        tenant,
        permissions,
    })
}

/// 本端点的 router,composition root 挂 frontend 组(app 进程,policy 权威侧)。
#[must_use]
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_my_permissions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::tenant_id::DEFAULT_TENANT_ID;

    fn user(roles: &[&str]) -> AuthUser {
        AuthUser::new(
            Uuid::nil(),
            "u".to_owned(),
            roles.iter().map(|s| s.to_string()).collect(),
        )
    }

    fn member(tenant_roles: &[&str]) -> AuthUser {
        user(&[]).in_tenant(
            DEFAULT_TENANT_ID.as_uuid(),
            tenant_roles.iter().map(|s| s.to_string()).collect(),
        )
    }

    // ── 组闸中间件:小 Router + Extension 注入,黑盒断言状态码 ──
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{middleware, Router};
    use tower::ServiceExt;

    async fn gate_status(app: Router, uri: &str) -> StatusCode {
        app.oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    /// require_login:无 AuthUser → 401;有 → 放行。
    #[tokio::test]
    async fn require_login_gates_unauthenticated() {
        let app = Router::new()
            .route("/t", get(|| async { "ok" }))
            .layer(middleware::from_fn(require_login));
        assert_eq!(gate_status(app, "/t").await, StatusCode::UNAUTHORIZED);

        let app = Router::new()
            .route("/t", get(|| async { "ok" }))
            .layer(middleware::from_fn(require_login))
            .layer(Extension(user(&["user"]))); // 外层先跑,注入 AuthUser
        assert_eq!(gate_status(app, "/t").await, StatusCode::OK);
    }

    /// require_admin_login:401(未登录)/ 403(role 无 perm)/ 403(role 够但 scope 收窄)/ 放行。
    #[tokio::test]
    async fn require_admin_login_gates_role_and_scope() {
        let policy = Arc::new(Policy::new([(
            "root".to_owned(),
            vec![Permission::AdminLogin],
        )]));
        let build_app = |user: Option<AuthUser>, scope: Option<TokenScope>| {
            let mut app = Router::new().route("/t", get(|| async { "ok" })).layer(
                middleware::from_fn_with_state(policy.clone(), require_admin_login),
            );
            if let Some(user) = user {
                app = app.layer(Extension(user));
            }
            if let Some(scope) = scope {
                app = app.layer(Extension(scope));
            }
            app
        };
        // 未登录 → 401
        assert_eq!(
            gate_status(build_app(None, None), "/t").await,
            StatusCode::UNAUTHORIZED
        );
        // role 无 admin:login → 403
        assert_eq!(
            gate_status(build_app(Some(member(&["user"])), None), "/t").await,
            StatusCode::FORBIDDEN
        );
        // role 够、scope 收窄(未含 admin:login)→ 403(降权令牌不得穿闸)
        assert_eq!(
            gate_status(
                build_app(
                    Some(member(&["root"])),
                    Some(TokenScope(vec![Permission::WidgetRead]))
                ),
                "/t"
            )
            .await,
            StatusCode::FORBIDDEN
        );
        // role 够、scope 空(满权令牌)→ 放行
        assert_eq!(
            gate_status(build_app(Some(member(&["root"])), None), "/t").await,
            StatusCode::OK
        );
        // admin:login 是租户级:同样的角色当平台角色、没有当前租户 → 403(tenant_required)
        assert_eq!(
            gate_status(build_app(Some(user(&["root"])), None), "/t").await,
            StatusCode::FORBIDDEN
        );
        // 平台管理员(平台角色给了平台级权限):不在任何租户里也能过闸
        let policy = Arc::new(Policy::new([(
            "platform".to_owned(),
            vec![Permission::UsersAdmin],
        )]));
        let app = Router::new()
            .route("/t", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(policy, require_admin_login))
            .layer(Extension(user(&["platform"])));
        assert_eq!(gate_status(app, "/t").await, StatusCode::OK);
    }

    /// 手写的闭集 schema 与 serde 同源:枚举值逐个等于 wire 串。
    #[test]
    fn closed_enum_schemas_list_wire_values() {
        use utoipa::PartialSchema;
        let json = serde_json::to_value(PermissionSchema::schema()).unwrap();
        let values = json["enum"].as_array().unwrap();
        assert_eq!(values.len(), Permission::ALL.len());
        assert_eq!(values[0], serde_json::to_value(Permission::ALL[0]).unwrap());
        let json = serde_json::to_value(RoleNameSchema::schema()).unwrap();
        assert_eq!(json["enum"].as_array().unwrap().len(), RoleName::ALL.len());
    }
}
