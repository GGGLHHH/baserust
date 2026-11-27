//! OpenAPI 文档:文档根 [`ApiDoc`]、oauth2 scope 声明、按 [`crate::infra::operation_permissions`] 表给每个
//! operation 注入 `security`(含 admin 组闸与条件权限),以及 `/docs` 与 `/api-docs/*` 路由。

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::Value;
use utoipa::openapi::path::Operation;
use utoipa::openapi::security::{
    Flow, OAuth2, Password, Scopes, SecurityRequirement, SecurityScheme,
};
// `utoipa::OpenApi` 是派生 trait,`utoipa::openapi::OpenApi` 是文档本身 —— 同名,后者改名区分。
use utoipa::openapi::OpenApi as OpenApiSpec;
use utoipa::{Modify, OpenApi};
use utoipa_scalar::{Scalar, Servable};

use crate::app::app_state::AppState;
use crate::features::users::adapters::http::dto::UserSortField;
use crate::features::widget::adapters::http::dto::WidgetSortField;
use crate::infra::http::error::ApiError;
use crate::infra::http::sort_order::SortOrder;
use crate::infra::operation_permissions::{
    conditional_permissions, operation_authorization, PermissionRequirement,
};
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::{self, Permission};

/// OpenAPI 文档根。范式:
/// - 顶层 info/tags 在此声明;path 与 schema 由各模块的 `#[utoipa::path]` + `routes!()` 贡献。
/// - `split_for_parts()` 把所有模块的规范合并成一份。
#[derive(OpenApi)]
#[openapi(
    info(title = "baserust API", version = "0.1.0", description = "Rust 脚手架"),
    // query 参数枚举:utoipa 只自动收集 responses/request_body 可达的 schema,
    // IntoParams 字段用的 ToSchema 枚举不会被收集(utoipa#1388)—— 必须在此显式声明,否则 spec 出悬空 $ref。
    // 下面三个**只**出现在 query 参数里,无响应体承载;有响应体承载的(如 RoleName ← AdminUserView.roles)
    // 会被传递收集,登记反而冗余。加错/漏加由 `no_dangling_schema_refs` 兜。
    components(schemas(SortOrder, WidgetSortField, UserSortField)),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "健康检查"),
        (name = "widgets", description = "示例资源"),
        (name = "contents", description = "内容/对象存储:CRUD / 上传下载 / 元数据"),
        (name = "profiles", description = "用户资料:姓名/电话/头像(头像经 content 富化)"),
        (name = "auth", description = "认证:注册/登录/刷新/登出"),
        (name = "me", description = "当前用户:资料/改密/注销"),
        (name = "admin", description = "后台:管理端登录/当前管理员"),
        (name = "users", description = "后台账号管理(平台级):CRUD/平台角色/密码/资料/认证审计"),
        (name = "tenants", description = "平台租户管理(平台级):建 / 改名 / 停用租户,管理任意租户的成员"),
        (name = "members", description = "本租户成员管理(租户级):成员列表 / 按用户名加入已有账号 / 设租户角色 / 移出"),
        (name = "monitoring", description = "系统监控:后台监控页(依赖健康/流量/数据库/后台任务/进程资源)与前端错误上报")
    )
)]
pub struct ApiDoc;

/// oauth2 scheme 名 —— 端点 `security(("oauth2" = [...]))` 引用须一字不差(裸串无编译期校验,靠测试兜)。
pub const OAUTH2_SCHEME: &str = "oauth2";

/// **标准方案**:OpenAPI 规范内,唯一能结构化承载"端点需哪个权限"的位置 = **oauth2 scheme 的 scopes**
/// (scope 只对 oauth2/oidc 有意义,apiKey/http 必须空)。把 cookie 优先 / Bearer 兜底的 JWT 登录,
/// 文档映射成 oauth2 **password flow**(tokenUrl→/public/auth/login、refreshUrl→/public/auth/refresh,相对路径守零环境变量启动)。
/// scopes 由 [`Permission::ALL`] 派生 —— scope key 与端点引用、与运行期 `require_scoped` 比较的 wire 串**同源**,杜绝漂移。
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut OpenApiSpec) {
        let components = openapi.components.get_or_insert_with(Default::default);
        let scope_docs = Permission::ALL
            .iter()
            .map(|&permission| (permission_wire(permission), permission_doc(permission)));
        let scopes = Scopes::from_iter(scope_docs);
        components.add_security_scheme(
            OAUTH2_SCHEME,
            SecurityScheme::OAuth2(OAuth2::with_description(
                [Flow::Password(Password::with_refresh_url(
                    "/api/v1/public/auth/login",
                    scopes,
                    "/api/v1/public/auth/refresh",
                ))],
                "JWT 认证。Token 由 POST /api/v1/public/auth/login(JSON identifier+password)签发,经 httponly \
                 `access_token` cookie 优先、`Authorization: Bearer <token>` 兜底两种方式发送。scopes 为 \
                 baserust 权限(由 role 授予;降权令牌有效 scope = role 权限 ∩ per-token scope)。注:本服务无独立 \
                 OAuth2 授权服务器,此 password flow 仅为对上述登录的文档映射,交互式 Authorize 不保证可直接调通。",
            )),
        );
    }
}

/// `Permission` → wire 串。委托 [`Permission::wire`](单一实现;`perm_wire_matches_projection` 钉死
/// 投影 == serde wire,JWT/TOML/`require_scoped`/`permissions/me` 同一串,零漂移)。
fn permission_wire(permission: Permission) -> String {
    permission.wire()
}

/// scope 人读说明:同样从投影合成,全静态、零 `seed.toml` 依赖(静态 `Modify` 本就拿不到运行时数据)。
fn permission_doc(permission: Permission) -> String {
    match permission.qualifier() {
        Some(qualifier) => format!(
            "{} {} ({qualifier})",
            permission.action(),
            permission.resource()
        ),
        None => format!("{} {}", permission.action(), permission.resource()),
    }
}

/// **OpenAPI 文档授权的单一来源注入**:按 operationId 从 [`crate::infra::operation_permissions::OPERATION_PERMISSIONS`] 表
/// 写每个 operation 的 `security`。删掉了所有手敲 `security(...)` 属性 → 系统内零 scope 串、
/// 改 `Permission` 必过编译期表 → 文档侧零漂移。`PermissionRequirement::LoginOnly` → `[{"oauth2":[]}]`(仅登录);
/// `All` → 单 requirement 多 scope(AND);`Any` → 多 requirement 各一 scope(OR);
/// 不在表 → 不写(public)。
///
/// **必须在 `split_for_parts()` 之后跑**:`modifiers(&SecurityAddon)` 在 `ApiDoc::openapi()` 那一刻执行,
/// 那时 paths 还空(utoipa-axum 在 merge/nest 后才填 operation),够不到 per-operation。
pub fn inject_operation_security(api: &mut OpenApiSpec) {
    for (path, item) in &mut api.paths.paths {
        // admin 组:组闸(admin:login 准入)并入文档 —— OpenAPI 无组级 security,组语义只能落在每个 operation 上。
        let admin_group = path.starts_with("/api/v1/admin/");
        let operations = [
            item.get.as_mut(),
            item.put.as_mut(),
            item.post.as_mut(),
            item.delete.as_mut(),
            item.patch.as_mut(),
        ];
        for operation in operations.into_iter().flatten() {
            let Some(id) = operation.operation_id.as_deref() else {
                continue;
            };
            let Some(entry) = operation_authorization(id) else {
                continue; // 不在表 = public,不写 security
            };
            // PermissionRequirement → OpenAPI:All = 单 requirement 多 scope(AND);Any = 多 requirement 各一 scope(OR);
            // LoginOnly = 单 requirement 空 scopes(**不可** `default()` —— 那是 {} = 无认证,语义错)。
            let mut requirements: Vec<Vec<String>> = match entry.permission {
                PermissionRequirement::LoginOnly => vec![Vec::new()],
                PermissionRequirement::All(permissions) => {
                    vec![permissions
                        .iter()
                        .map(|&permission| permission_wire(permission))
                        .collect()]
                }
                PermissionRequirement::Any(permissions) => permissions
                    .iter()
                    .map(|&permission| vec![permission_wire(permission)])
                    .collect(),
            };
            if admin_group {
                requirements = with_admin_entry(&requirements);
            }
            operation.security = Some(
                requirements
                    .into_iter()
                    .map(|scopes| SecurityRequirement::new(OAUTH2_SCHEME, scopes))
                    .collect(),
            );
            // operation_id 借自 operation,下面要可变借 operation —— 先拷一份 id。
            let id = id.to_owned();
            inject_conditional_scopes(operation, &id);
        }
    }
}

/// 条件权限([`crate::infra::operation_permissions::CONDITIONAL_PERMISSIONS`])→ operation 的 `x-conditional-scopes` 扩展
/// (`[{"when": …, "scopes": […]}]`,机读)+ description 末尾一句(人读)。security 是静态的,表达不了条件闸。
fn inject_conditional_scopes(operation: &mut Operation, id: &str) {
    let conditionals: Vec<_> = conditional_permissions(id).collect();
    if conditionals.is_empty() {
        return;
    }
    let mut machine: Vec<Value> = Vec::with_capacity(conditionals.len());
    let mut notes: Vec<String> = Vec::with_capacity(conditionals.len());
    for conditional in &conditionals {
        let scopes: Vec<String> = conditional
            .permissions
            .iter()
            .map(|&permission| permission_wire(permission))
            .collect();
        let quoted: Vec<String> = scopes.iter().map(|scope| format!("`{scope}`")).collect();
        notes.push(format!(
            "条件权限:{}另需 {}(缺 → 403)。",
            conditional.when.describe(),
            quoted.join(" + ")
        ));
        machine.push(serde_json::json!({
            "when": conditional.when.wire(),
            "scopes": scopes,
        }));
    }
    operation
        .extensions
        .get_or_insert_with(Default::default)
        .insert("x-conditional-scopes".to_owned(), machine.into());
    let note = notes.join("\n");
    operation.description = Some(match operation.description.take() {
        Some(description) if !description.is_empty() => format!("{description}\n\n{note}"),
        _ => note,
    });
}

/// admin 组闸(后台准入 = `admin:login` **或**任一平台级权限,见 `Policy::require_admin_entry`)并入文档:
/// 组闸拦**所有**分支,而准入本身是 OR → 每个 requirement × 每个准入权限取并集(AND),再删掉被更小
/// requirement 蕴含的(A ⊂ B 时满足 B 必满足 A,B 多余)。准入清单与执行同源(`admin_entry_permissions`)。
fn with_admin_entry(requirements: &[Vec<String>]) -> Vec<Vec<String>> {
    let gates: Vec<String> = authorization::admin_entry_permissions()
        .into_iter()
        .map(permission_wire)
        .collect();
    let mut combined_requirements: Vec<Vec<String>> = Vec::new();
    for requirement in requirements {
        for gate in &gates {
            let mut combined = requirement.clone();
            if !combined.contains(gate) {
                combined.push(gate.clone());
            }
            if !combined_requirements
                .iter()
                .any(|existing| same_set(existing, &combined))
            {
                combined_requirements.push(combined);
            }
        }
    }
    // A ⊂ B(A 更小且全被 B 包含)时 B 多余,只留最小的那些。
    let is_implied = |candidate: &[String]| {
        combined_requirements.iter().any(|smaller| {
            smaller.len() < candidate.len() && smaller.iter().all(|scope| candidate.contains(scope))
        })
    };
    combined_requirements
        .iter()
        .filter(|candidate| !is_implied(candidate.as_slice()))
        .cloned()
        .collect()
}

fn same_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|s| right.contains(s))
}

/// 暴露 `/api-docs/openapi.json` 与 `/api-docs/openapi.yaml`。
/// yaml 用 utoipa 自带的 `to_yaml()`(yaml feature),整条绕开 2026 混乱的 serde_yaml 生态。
pub fn doc_routes(api: OpenApiSpec) -> Router<AppState> {
    // 三个路由各持一份(Scalar 拿走原件,两个 handler 各要一份可 'static 的拷贝)。
    let json_api = api.clone();
    let yaml_api = api.clone();
    Router::new()
        // Scalar UI:类似 huma 的可视化文档页,读合并后的 OpenAPI 规范
        .merge(Scalar::with_url("/docs", api))
        .route(
            "/api-docs/openapi.json",
            get(move || {
                let api = json_api.clone();
                async move { axum::Json(api) }
            }),
        )
        .route(
            "/api-docs/openapi.yaml",
            get(move || {
                let api = yaml_api.clone();
                async move { yaml_response(&api) }
            }),
        )
}

fn yaml_response(api: &OpenApiSpec) -> Response {
    match api.to_yaml() {
        Ok(body) => ([(header::CONTENT_TYPE, "application/yaml")], body).into_response(),
        Err(error) => ApiError::from(AppError::Internal(anyhow::anyhow!(
            "生成 OpenAPI YAML 失败: {error}"
        )))
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::app::router;
    use crate::infra::operation_permissions::{CONDITIONAL_PERMISSIONS, OPERATION_PERMISSIONS};

    /// 合规 + 稳定:① 声明的 oauth2 scopes == `Permission` 闭集 wire 串(catalog parity);
    /// ② 每个端点 `security` 引用的 oauth2 scope ⊆ 声明集(used ⊆ declared)。
    /// 任何端点 scope 拼错 / 漏声明 → 这里红;杜绝 spec 出现悬空 scope(通用校验器也会拒)。
    #[test]
    fn security_scopes_declared_and_within_catalog() {
        let spec = serde_json::to_value(router::api_spec()).unwrap();

        let declared: BTreeSet<String> = spec["components"]["securitySchemes"][OAUTH2_SCHEME]
            ["flows"]["password"]["scopes"]
            .as_object()
            .expect("oauth2 password scopes 应存在")
            .keys()
            .cloned()
            .collect();
        let catalog: BTreeSet<String> = Permission::ALL
            .iter()
            .map(|p| permission_wire(*p))
            .collect();
        assert_eq!(
            declared, catalog,
            "声明的 scopes 应 == Permission 闭集 wire 串"
        );

        for (_path, item) in spec["paths"].as_object().expect("paths").iter() {
            for (_method, operation) in item.as_object().expect("path item").iter() {
                let Some(requirements) = operation.get("security").and_then(|s| s.as_array())
                else {
                    continue;
                };
                for requirement in requirements {
                    let Some(scopes) = requirement.get(OAUTH2_SCHEME).and_then(|s| s.as_array())
                    else {
                        continue;
                    };
                    for scope in scopes {
                        let scope = scope.as_str().unwrap();
                        assert!(
                            declared.contains(scope),
                            "端点引用了未声明的 scope `{scope}`"
                        );
                    }
                }
            }
        }
    }

    /// **fail-closed**:spec 里每个 `$ref` 必须在 `components.schemas` 有条目。
    /// utoipa 不做任何校验,而 `IntoParams` 字段上的 `ToSchema` 枚举**不被**自动收集(utoipa#1388)——
    /// 漏在 `components(schemas(..))` 登记就静默出悬空 ref:Scalar 渲染成空 schema、前端 codegen 出断类型。
    /// 反向也兜:登记了已被传递收集的类型只是冗余,不会在此红,靠 review 删。
    #[test]
    fn no_dangling_schema_refs() {
        fn collect(value: &Value, out: &mut BTreeSet<String>) {
            match value {
                Value::Object(object) => {
                    if let Some(reference) =
                        object.get("$ref").and_then(|reference| reference.as_str())
                    {
                        out.insert(reference.to_owned());
                    }
                    for child in object.values() {
                        collect(child, out);
                    }
                }
                Value::Array(array) => {
                    for element in array {
                        collect(element, out);
                    }
                }
                _ => {}
            }
        }

        let spec = serde_json::to_value(router::api_spec()).unwrap();
        let mut references = BTreeSet::new();
        collect(&spec, &mut references);
        assert!(
            !references.is_empty(),
            "spec 一个 $ref 都没有?schema 收集坏了"
        );

        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("components.schemas 应存在");
        for reference in &references {
            let name = reference
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("非 components.schemas 的 $ref:`{reference}`"));
            assert!(
                schemas.contains_key(name),
                "悬空 $ref:`{reference}` 不在 components.schemas —— \
                 若该类型只出现在 IntoParams 字段上,去 ApiDoc 的 components(schemas(..)) 显式登记"
            );
        }
    }

    /// **fail-closed**:spec 每个 operation 必在 `OPERATION_PERMISSIONS` 或 public 白名单 —— 新端点漏授权(无 security 注入)即红。
    #[test]
    fn every_operation_classified() {
        const PUBLIC: &[&str] = &[
            "register",
            "login",
            "refresh",
            "logout",
            "livez",
            "health",
            "readyz",
            "report_client_errors", // 前端错误上报:登录页也要能报,靠限流 + 截断设防
            "admin_login",          // 验密后 handler 自查 admin:login,非表驱动
        ];
        let spec = serde_json::to_value(router::api_spec()).unwrap();
        for (_path, item) in spec["paths"].as_object().expect("paths").iter() {
            for (_method, operation) in item.as_object().expect("path item").iter() {
                let Some(id) = operation.get("operationId").and_then(|x| x.as_str()) else {
                    continue;
                };
                assert!(
                    operation_authorization(id).is_some() || PUBLIC.contains(&id),
                    "operation `{id}` 未分类:加进 OPERATION_PERMISSIONS 或 public 白名单(fail-closed)"
                );
            }
        }
    }

    /// 防表腐:`OPERATION_PERMISSIONS` 每个 operationId 必在 spec 存在(handler 改名 / 路径漂移 → 这里红)。
    #[test]
    fn operation_permissions_entries_exist_in_spec() {
        let spec = serde_json::to_value(router::api_spec()).unwrap();
        let ids: BTreeSet<String> = spec["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item.as_object().unwrap().values())
            .filter_map(|operation| {
                operation
                    .get("operationId")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned)
            })
            .collect();
        for entry in OPERATION_PERMISSIONS {
            assert!(
                ids.contains(entry.operation_id),
                "OPERATION_PERMISSIONS 的 `{}` 在 spec 不存在(handler 改名/路径漂移?)",
                entry.operation_id
            );
        }
    }

    /// 防表腐:`CONDITIONAL_PERMISSIONS` 每个 operationId 必在 spec 存在,且 operation 带着它的 `x-conditional-scopes`
    /// 条目(`{when, scopes}` 与表一致)。条件权限只随 `OPERATION_PERMISSIONS` 注入(不在 `OPERATION_PERMISSIONS` = public → 不写),
    /// 所以 handler 改名 / 路径漂移 / 漏登 `OPERATION_PERMISSIONS` 都会让文档静默丢掉条件权限 → 这里红。
    #[test]
    fn op_conditional_perms_entries_documented_in_spec() {
        let spec = serde_json::to_value(router::api_spec()).unwrap();
        let operations: Vec<&Value> = spec["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item.as_object().unwrap().values())
            .collect();
        for conditional in CONDITIONAL_PERMISSIONS {
            let operation = operations
                .iter()
                .find(|candidate| {
                    candidate.get("operationId").and_then(|x| x.as_str())
                        == Some(conditional.operation_id)
                })
                .unwrap_or_else(|| {
                    panic!(
                        "CONDITIONAL_PERMISSIONS 的 `{}` 在 spec 不存在(handler 改名/路径漂移?)",
                        conditional.operation_id
                    )
                });
            let extension = operation
                .get("x-conditional-scopes")
                .and_then(|x| x.as_array())
                .unwrap_or_else(|| {
                    panic!(
                        "`{}` 在 spec 里没有 x-conditional-scopes(没登记进 OPERATION_PERMISSIONS?条件权限只随它注入)",
                        conditional.operation_id
                    )
                });
            let want = serde_json::json!({
                "when": conditional.when.wire(),
                "scopes": conditional.permissions.iter().map(|&p| permission_wire(p)).collect::<Vec<_>>(),
            });
            assert!(
                extension.contains(&want),
                "`{}` 的 x-conditional-scopes 缺条目 {want},got {extension:?}",
                conditional.operation_id
            );
        }
    }

    /// admin 组注入:`/api/v1/admin/` 下**表内** op 的每个 requirement 都含一个后台准入权限
    /// (`admin:login` 或平台级权限;组闸=后台准入进文档,文档不骗人);仅登录的 op 恰好是「每个准入权限一支」。
    /// 不在表(admin_login)= public,无 security,跳过。
    #[test]
    fn admin_group_ops_carry_admin_entry_scope() {
        let spec = serde_json::to_value(router::api_spec()).unwrap();
        let entry: Vec<String> = authorization::admin_entry_permissions()
            .into_iter()
            .map(permission_wire)
            .collect();
        let mut seen = 0;
        for (path, item) in spec["paths"].as_object().expect("paths").iter() {
            if !path.starts_with("/api/v1/admin/") {
                continue;
            }
            for (_method, operation) in item.as_object().expect("path item").iter() {
                let Some(id) = operation.get("operationId").and_then(|x| x.as_str()) else {
                    continue;
                };
                let Some(requirements) = operation.get("security").and_then(|s| s.as_array())
                else {
                    continue; // public(admin_login)
                };
                for requirement in requirements {
                    let scopes: Vec<&str> = requirement[OAUTH2_SCHEME]
                        .as_array()
                        .expect("oauth2 scopes")
                        .iter()
                        .map(|s| s.as_str().unwrap())
                        .collect();
                    assert!(
                        scopes.iter().any(|s| entry.iter().any(|e| e == s)),
                        "admin 组 `{id}` 每个 requirement 都应含一个后台准入权限,got {scopes:?}"
                    );
                }
                if id == "admin_get_me" {
                    let branches: Vec<Vec<String>> = requirements
                        .iter()
                        .map(|requirement| {
                            requirement[OAUTH2_SCHEME]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|s| s.as_str().unwrap().to_owned())
                                .collect()
                        })
                        .collect();
                    let expect: Vec<Vec<String>> = entry.iter().map(|e| vec![e.clone()]).collect();
                    assert_eq!(branches, expect, "仅登录的 admin op = 每个准入权限一支(OR)");
                }
                seen += 1;
            }
        }
        assert!(seen >= 2, "admin 组应至少 2 个带 security 的 op,got {seen}");
    }

    /// 多权限文档形状:AND = 单 requirement 多 scope;OR = 多 requirement 各一 scope。
    /// 断言含顺序(= 表内数组顺序)—— 形状即契约。
    #[test]
    fn multi_perm_doc_shapes() {
        let spec = serde_json::to_value(router::api_spec()).unwrap();
        let find = |target: &str| -> Vec<Vec<String>> {
            for (_path, item) in spec["paths"].as_object().unwrap() {
                for (_method, operation) in item.as_object().unwrap() {
                    if operation.get("operationId").and_then(|x| x.as_str()) == Some(target) {
                        return operation["security"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|requirement| {
                                requirement["oauth2"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|s| s.as_str().unwrap().to_owned())
                                    .collect()
                            })
                            .collect();
                    }
                }
            }
            panic!("spec 缺 operation `{target}`");
        };
        assert_eq!(
            find("purge_preview"),
            vec![vec!["widgets:read".to_owned(), "widgets:delete".to_owned()]],
            "AND 应是单 requirement 双 scope"
        );
        assert_eq!(
            find("widget_overview"),
            vec![
                vec!["widgets:read".to_owned()],
                vec!["members:admin".to_owned()]
            ],
            "OR 应是双 requirement 各单 scope"
        );
    }
}
