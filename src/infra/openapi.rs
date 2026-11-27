use crate::infra::http::error::ApiError;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use utoipa::openapi::security::{
    Flow, OAuth2, Password, Scopes, SecurityRequirement, SecurityScheme,
};
use utoipa::{Modify, OpenApi};
use utoipa_scalar::{Scalar, Servable};

use crate::app::state::AppState;
use crate::infra::op_perms::{op_authz, op_conditional, PermReq};
use crate::kernel::authz::Perm;
use crate::kernel::error::AppError;

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
    components(schemas(
        crate::infra::http::sort::SortOrder,
        crate::features::widget::adapters::http::dto::WidgetSortField,
        crate::features::users::adapters::http::dto::UserSortField,
    )),
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
/// scopes 由 [`Perm::ALL`] 派生 —— scope key 与端点引用、与运行期 `require_scoped` 比较的 wire 串**同源**,杜绝漂移。
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        let scopes = Scopes::from_iter(Perm::ALL.iter().map(|p| (perm_wire(*p), perm_doc(*p))));
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

/// `Perm` → wire 串。委托 [`Perm::wire`](单一实现;`perm_wire_matches_projection` 钉死
/// 投影 == serde wire,JWT/TOML/`require_scoped`/`permissions/me` 同一串,零漂移)。
fn perm_wire(p: Perm) -> String {
    p.wire()
}

/// scope 人读说明:同样从投影合成,全静态、零 `seed.toml` 依赖(静态 `Modify` 本就拿不到运行时数据)。
fn perm_doc(p: Perm) -> String {
    match p.qualifier() {
        Some(q) => format!("{} {} ({q})", p.action(), p.resource()),
        None => format!("{} {}", p.action(), p.resource()),
    }
}

/// **OpenAPI 文档授权的单一来源注入**:按 operationId 从 [`crate::infra::op_perms::OP_PERMS`] 表
/// 写每个 operation 的 `security`。删掉了所有手敲 `security(...)` 属性 → 系统内零 scope 串、
/// 改 `Perm` 必过编译期表 → 文档侧零漂移。`PermReq::LoginOnly` → `[{"oauth2":[]}]`(仅登录);
/// `All` → 单 requirement 多 scope(AND);`Any` → 多 requirement 各一 scope(OR);
/// 不在表 → 不写(public)。
///
/// **必须在 `split_for_parts()` 之后跑**:`modifiers(&SecurityAddon)` 在 `ApiDoc::openapi()` 那一刻执行,
/// 那时 paths 还空(utoipa-axum 在 merge/nest 后才填 operation),够不到 per-operation。
pub fn inject_operation_security(api: &mut utoipa::openapi::OpenApi) {
    for (path, item) in api.paths.paths.iter_mut() {
        // admin 组:组闸(admin:login 准入)并入文档 —— OpenAPI 无组级 security,组语义只能落在每个 operation 上。
        let admin_group = path.starts_with("/api/v1/admin/");
        let ops = [
            item.get.as_mut(),
            item.put.as_mut(),
            item.post.as_mut(),
            item.delete.as_mut(),
            item.patch.as_mut(),
        ];
        for op in ops.into_iter().flatten() {
            let Some(id) = op.operation_id.as_deref() else {
                continue;
            };
            let Some(e) = op_authz(id) else {
                continue; // 不在表 = public,不写 security
            };
            // PermReq → OpenAPI:All = 单 requirement 多 scope(AND);Any = 多 requirement 各一 scope(OR);
            // LoginOnly = 单 requirement 空 scopes(**不可** `default()` —— 那是 {} = 无认证,语义错)。
            let mut reqs: Vec<Vec<String>> = match e.perm {
                PermReq::LoginOnly => vec![Vec::new()],
                PermReq::All(ps) => vec![ps.iter().map(|&p| perm_wire(p)).collect()],
                PermReq::Any(ps) => ps.iter().map(|&p| vec![perm_wire(p)]).collect(),
            };
            if admin_group {
                reqs = with_admin_entry(reqs);
            }
            op.security = Some(
                reqs.into_iter()
                    .map(|scopes| SecurityRequirement::new(OAUTH2_SCHEME, scopes))
                    .collect(),
            );
            let id = id.to_owned();
            inject_conditional_scopes(op, &id);
        }
    }
}

/// 条件权限([`crate::infra::op_perms::OP_CONDITIONAL_PERMS`])→ operation 的 `x-conditional-scopes` 扩展
/// (`[{"when": …, "scopes": […]}]`,机读)+ description 末尾一句(人读)。security 是静态的,表达不了条件闸。
fn inject_conditional_scopes(op: &mut utoipa::openapi::path::Operation, id: &str) {
    let conds: Vec<_> = op_conditional(id).collect();
    if conds.is_empty() {
        return;
    }
    let machine: Vec<serde_json::Value> = conds
        .iter()
        .map(|c| {
            serde_json::json!({
                "when": c.when.wire(),
                "scopes": c.perms.iter().map(|&p| perm_wire(p)).collect::<Vec<_>>(),
            })
        })
        .collect();
    op.extensions
        .get_or_insert_with(Default::default)
        .insert("x-conditional-scopes".to_owned(), machine.into());
    let note = conds
        .iter()
        .map(|c| {
            let scopes: Vec<String> = c
                .perms
                .iter()
                .map(|&p| format!("`{}`", perm_wire(p)))
                .collect();
            format!(
                "条件权限:{}另需 {}(缺 → 403)。",
                c.when.describe(),
                scopes.join(" + ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    op.description = Some(match op.description.take() {
        Some(d) if !d.is_empty() => format!("{d}\n\n{note}"),
        _ => note,
    });
}

/// admin 组闸(后台准入 = `admin:login` **或**任一平台级权限,见 `Policy::require_admin_entry`)并入文档:
/// 组闸拦**所有**分支,而准入本身是 OR → 每个 requirement × 每个准入权限取并集(AND),再删掉被更小
/// requirement 蕴含的(A ⊂ B 时满足 B 必满足 A,B 多余)。准入清单与执行同源(`admin_entry_perms`)。
fn with_admin_entry(reqs: Vec<Vec<String>>) -> Vec<Vec<String>> {
    let gates: Vec<String> = crate::kernel::authz::admin_entry_perms()
        .into_iter()
        .map(perm_wire)
        .collect();
    let mut out: Vec<Vec<String>> = Vec::new();
    for r in &reqs {
        for g in &gates {
            let mut combined = r.clone();
            if !combined.contains(g) {
                combined.push(g.clone());
            }
            if !out.iter().any(|o| same_set(o, &combined)) {
                out.push(combined);
            }
        }
    }
    let minimal: Vec<Vec<String>> = out
        .iter()
        .filter(|b| {
            !out.iter()
                .any(|a| a.len() < b.len() && a.iter().all(|s| b.contains(s)))
        })
        .cloned()
        .collect();
    minimal
}

fn same_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|s| b.contains(s))
}

/// 暴露 `/api-docs/openapi.json` 与 `/api-docs/openapi.yaml`。
/// yaml 用 utoipa 自带的 `to_yaml()`(yaml feature),整条绕开 2026 混乱的 serde_yaml 生态。
pub fn doc_routes(api: utoipa::openapi::OpenApi) -> Router<AppState> {
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

fn yaml_response(api: &utoipa::openapi::OpenApi) -> Response {
    match api.to_yaml() {
        Ok(body) => ([(header::CONTENT_TYPE, "application/yaml")], body).into_response(),
        Err(e) => ApiError::from(AppError::Internal(anyhow::anyhow!(
            "生成 OpenAPI YAML 失败: {e}"
        )))
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// 合规 + 稳定:① 声明的 oauth2 scopes == `Perm` 闭集 wire 串(catalog parity);
    /// ② 每个端点 `security` 引用的 oauth2 scope ⊆ 声明集(used ⊆ declared)。
    /// 任何端点 scope 拼错 / 漏声明 → 这里红;杜绝 spec 出现悬空 scope(通用校验器也会拒)。
    #[test]
    fn security_scopes_declared_and_within_catalog() {
        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();

        let declared: BTreeSet<String> = v["components"]["securitySchemes"][OAUTH2_SCHEME]["flows"]
            ["password"]["scopes"]
            .as_object()
            .expect("oauth2 password scopes 应存在")
            .keys()
            .cloned()
            .collect();
        let catalog: BTreeSet<String> = Perm::ALL.iter().map(|p| perm_wire(*p)).collect();
        assert_eq!(declared, catalog, "声明的 scopes 应 == Perm 闭集 wire 串");

        for (_path, item) in v["paths"].as_object().expect("paths").iter() {
            for (_method, op) in item.as_object().expect("path item").iter() {
                let Some(reqs) = op.get("security").and_then(|s| s.as_array()) else {
                    continue;
                };
                for req in reqs {
                    let Some(scopes) = req.get(OAUTH2_SCHEME).and_then(|s| s.as_array()) else {
                        continue;
                    };
                    for s in scopes {
                        let s = s.as_str().unwrap();
                        assert!(declared.contains(s), "端点引用了未声明的 scope `{s}`");
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
        fn collect(v: &serde_json::Value, out: &mut BTreeSet<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    if let Some(r) = m.get("$ref").and_then(|r| r.as_str()) {
                        out.insert(r.to_owned());
                    }
                    for x in m.values() {
                        collect(x, out);
                    }
                }
                serde_json::Value::Array(a) => {
                    for x in a {
                        collect(x, out);
                    }
                }
                _ => {}
            }
        }

        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();
        let mut refs = BTreeSet::new();
        collect(&v, &mut refs);
        assert!(!refs.is_empty(), "spec 一个 $ref 都没有?schema 收集坏了");

        let schemas = v["components"]["schemas"]
            .as_object()
            .expect("components.schemas 应存在");
        for r in &refs {
            let name = r
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("非 components.schemas 的 $ref:`{r}`"));
            assert!(
                schemas.contains_key(name),
                "悬空 $ref:`{r}` 不在 components.schemas —— \
                 若该类型只出现在 IntoParams 字段上,去 ApiDoc 的 components(schemas(..)) 显式登记"
            );
        }
    }

    /// **fail-closed**:spec 每个 operation 必在 `OP_PERMS` 或 public 白名单 —— 新端点漏授权(无 security 注入)即红。
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
        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();
        for (_path, item) in v["paths"].as_object().expect("paths").iter() {
            for (_method, op) in item.as_object().expect("path item").iter() {
                let Some(id) = op.get("operationId").and_then(|x| x.as_str()) else {
                    continue;
                };
                assert!(
                    op_authz(id).is_some() || PUBLIC.contains(&id),
                    "operation `{id}` 未分类:加进 OP_PERMS 或 public 白名单(fail-closed)"
                );
            }
        }
    }

    /// 防表腐:`OP_PERMS` 每个 operationId 必在 spec 存在(handler 改名 / 路径漂移 → 这里红)。
    #[test]
    fn op_perms_entries_exist_in_spec() {
        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();
        let ids: BTreeSet<String> = v["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item.as_object().unwrap().values())
            .filter_map(|op| {
                op.get("operationId")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned)
            })
            .collect();
        for e in crate::infra::op_perms::OP_PERMS {
            assert!(
                ids.contains(e.operation_id),
                "OP_PERMS 的 `{}` 在 spec 不存在(handler 改名/路径漂移?)",
                e.operation_id
            );
        }
    }

    /// 防表腐:`OP_CONDITIONAL_PERMS` 每个 operationId 必在 spec 存在,且 operation 带着它的 `x-conditional-scopes`
    /// 条目(`{when, scopes}` 与表一致)。条件权限只随 `OP_PERMS` 注入(不在 `OP_PERMS` = public → 不写),
    /// 所以 handler 改名 / 路径漂移 / 漏登 `OP_PERMS` 都会让文档静默丢掉条件权限 → 这里红。
    #[test]
    fn op_conditional_perms_entries_documented_in_spec() {
        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();
        let ops: Vec<&serde_json::Value> = v["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item.as_object().unwrap().values())
            .collect();
        for c in crate::infra::op_perms::OP_CONDITIONAL_PERMS {
            let op = ops
                .iter()
                .find(|op| op.get("operationId").and_then(|x| x.as_str()) == Some(c.operation_id))
                .unwrap_or_else(|| {
                    panic!(
                        "OP_CONDITIONAL_PERMS 的 `{}` 在 spec 不存在(handler 改名/路径漂移?)",
                        c.operation_id
                    )
                });
            let ext = op
                .get("x-conditional-scopes")
                .and_then(|x| x.as_array())
                .unwrap_or_else(|| {
                    panic!(
                        "`{}` 在 spec 里没有 x-conditional-scopes(没登记进 OP_PERMS?条件权限只随它注入)",
                        c.operation_id
                    )
                });
            let want = serde_json::json!({
                "when": c.when.wire(),
                "scopes": c.perms.iter().map(|&p| perm_wire(p)).collect::<Vec<_>>(),
            });
            assert!(
                ext.contains(&want),
                "`{}` 的 x-conditional-scopes 缺条目 {want},got {ext:?}",
                c.operation_id
            );
        }
    }

    /// admin 组注入:`/api/v1/admin/` 下**表内** op 的每个 requirement 都含一个后台准入权限
    /// (`admin:login` 或平台级权限;组闸=后台准入进文档,文档不骗人);仅登录的 op 恰好是「每个准入权限一支」。
    /// 不在表(admin_login)= public,无 security,跳过。
    #[test]
    fn admin_group_ops_carry_admin_entry_scope() {
        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();
        let entry: Vec<String> = crate::kernel::authz::admin_entry_perms()
            .into_iter()
            .map(perm_wire)
            .collect();
        let mut seen = 0;
        for (path, item) in v["paths"].as_object().expect("paths").iter() {
            if !path.starts_with("/api/v1/admin/") {
                continue;
            }
            for (_method, op) in item.as_object().expect("path item").iter() {
                let Some(id) = op.get("operationId").and_then(|x| x.as_str()) else {
                    continue;
                };
                let Some(reqs) = op.get("security").and_then(|s| s.as_array()) else {
                    continue; // public(admin_login)
                };
                for req in reqs {
                    let scopes: Vec<&str> = req[OAUTH2_SCHEME]
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
                    let branches: Vec<Vec<String>> = reqs
                        .iter()
                        .map(|r| {
                            r[OAUTH2_SCHEME]
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
        let v = serde_json::to_value(crate::app::router::api_spec()).unwrap();
        let find = |target: &str| -> Vec<Vec<String>> {
            for (_p, item) in v["paths"].as_object().unwrap() {
                for (_m, op) in item.as_object().unwrap() {
                    if op.get("operationId").and_then(|x| x.as_str()) == Some(target) {
                        return op["security"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|r| {
                                r["oauth2"]
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
