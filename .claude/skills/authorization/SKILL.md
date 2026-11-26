---
name: authorization
description: Use when adding or changing an endpoint that needs auth, deciding who can call what, reasoning about why an endpoint returns 403 vs 404, how permissions appear in the OpenAPI docs, or whether to gate on a role.
---

# Authorization (app-owned)

The non-obvious **judgment** — stated so you get the critical calls right *even before* digging through the code. Mechanics (how to wire a gate) = **copy `widget`**: it has a sample of every shape (public / authenticated / perm-gated / ownership / multi-perm AND·OR / tenant-level endpoint inside the admin group); platform-level = copy `users` (gate platform `users:admin`) / `monitoring` (gate superadmin-only `ops:read`).

## perm is the only currency — never gate on a role

No `if role == "superadmin"` / `roles.contains(...)` in a handler. Effective auth = `role perms ∩ token scope`, so a raw role-string check **ignores `TokenScope`** → a deliberately down-scoped token (PAT / 3rd-party) sails through your most dangerous endpoint. "Only role X" = gate a `Perm` only X is granted in `seed.toml`. Note `Perm::UsersAdmin` is **platform-level** (platform_admin + superadmin) — gating on it locks tenant *admins* out; for an admin-able action, grant a perm to admin too (or add a dedicated `Perm`). Superadmin-only = `ops:read` / `audit:read` / `platform:roles` (`SUPERADMIN_ONLY`).

## access vs ownership — different categories

| | **access** (capability) | **ownership** (data visibility) |
|---|---|---|
| asks | can you call this? | which rows do you see? |
| where | edge: `require_scoped(perm)` | query/row: `data_access` → `owner_filter` / `allows_created_by` |
| denial | **403** | filtered list / single-row **404** |
| in OpenAPI | oauth2 scope on the op | **nothing** (prose + the 404 only) |

Non-owner hitting a row that exists → **404, not 403** (404 hides existence; 403 leaks it). A *new* endpoint that wrongly 403s is caught by **no** test — your copied test asserts whatever you wrote. Judgment, not test-enforced.

## read:all *switches ownership mode*, it isn't a gate

`widgets:read:all` is a grantable scope but **no endpoint requires it** — having it → `Access::All`, lacking it → `Access::Own`. Correct, not a missing gate.

## OpenAPI carries access, not ownership

oauth2 scopes = "which perm gates this op". Ownership is runtime/data-dependent → **not expressible**; document it in the response description + the 404. Don't invent an `x-` field.

## where each truth lives

| truth | file |
|---|---|
| which perms exist | `Perm` enum — `crates/core/src/kernel/authz.rs`(OpenAPI schema 标记类型 `PermSchema` 在 `src/infra/authz.rs`) |
| endpoint → perm (**docs**) | `infra/op_perms.rs` — add one row |
| endpoint → perm (**enforce**) | the handler's `require_scoped` |
| role → perms | `RoleName::default_permissions` → `role_permissions` 表(运行期可改) |
| perm 作用域 / 角色作用域 | `Perm::scope()` / `RoleName::scope()`(穷尽 match) |
| user → 租户 + 租户角色 | idm 成员关系 → JWT `tenant_id` / `tenant_roles`(`seed.toml` 的 `tenants = [...]`) |

Doc `security` is **injected from `op_perms`** after `split_for_parts` — **never hand-write `security(("oauth2"=...))` in `#[utoipa::path]`**; `every_operation_classified` fail-closes on an unclassified op.

## Red flags
- `if role == ...` / `roles.contains(...)` → gate a perm
- 403 for "not yours" → should be 404
- hand-written `security(("oauth2"=...))` in a path macro → add an `op_perms` row
- ownership rule going into OpenAPI `security` → it can't live there

## 多租户:作用域与当前租户(spec §4.3)

- 每个 `Perm` 有作用域:**平台级**(`users:admin` 账号管理、`tenants:admin` 租户管理、`ops:read` 监控、`audit:read` 认证审计、`platform:roles` 平台角色管理、`profiles:*`)只由**平台角色**(token `roles`)授予;**租户级**(其余)只由**当前租户角色**(`tenant_roles`)授予。平台角色**不**自动拿到任何租户的租户级权限。加 `Perm` = 在 `scope()` 的穷尽 match 里判断它属于哪类。
- token 没有当前租户(平台上下文)时要租户级权限 → `require_scoped` 直接 403 `tenant_required`。
- 租户级接口取租户**只用** `CurrentTenant` 提取器(`infra::http::audit`):租户只从 token 来,不收请求体 / 查询参数里的 `tenant_id`,缺了 403 `tenant_required`,**绝不落默认租户**。跨租户的资源 id → 404(同 ownership 口径)。
- 后台准入(`/admin` 组闸 + 后台登录)= 当前租户里的 `admin:login` **或**任一平台级权限(`Policy::require_admin_entry`;文档按 `admin_entry_perms()` 同源注入成 OR)。
- 后台登录**挑进哪里**(`Policy::admin_login_entry` + idm `login_with`):有效成员关系按 last_used 倒序挑第一个租户角色给了 `admin:login` 的租户;都没有 → 有平台级权限进平台上下文;否则 403(一个成员关系都没有 → `tenant_required`,有 → `forbidden`)。前台登录仍进最近用过的租户。
- **后台组里的租户级接口(读写租户数据)闸用租户级权限**(如 `admin_list_widgets` = `widgets:read`),不用平台级 `users:admin` —— 否则租户管理员进了后台也看不到菜单(前端 access-policies 由 OpenAPI 生成)。平台级权限只闸平台能力(账号、租户、监控、认证审计)。
- 闭集内角色的跨作用域 `role_permissions` 行启动载入时 WARN 并忽略(存量行已由迁移 `app/0007` 清掉,WARN 只为以后新出现的漂移)。
- 新模块的租户落地(核心收 `TenantId`、PG 走 `tenant_tx`、RLS 迁移、跨租户黑盒测试、`rls_audit`)→ `adding-a-feature` skill 的 Multi-tenancy 一节;本节只管「谁能调」。
- 账号是全局的:建号 / 改密 / 删号 = `users:admin`(平台级);授平台角色、动持平台角色的账号另要 `platform:roles`(见上一节)。租户管理员管的是**成员关系**(`members:read` / `members:admin`,租户级,`/admin/auth/members*`):按完整用户名把已有账号加进当前租户、设租户角色、移出 —— 成员 id 不在当前租户 → 404。平台管理员管任意租户走 `/admin/platform/tenants/{id}/members*`(`tenants:admin`)。

## 平台角色:superadmin 独占 + 平台管理员(2026-11-26)

- **角色**:平台角色 `superadmin`(只有一个)/ `platform_admin`;组织角色 `admin` / `user`。`platform_admin` 默认 = 全部平台级权限 − `SUPERADMIN_ONLY`(`ops:read` / `audit:read` / `platform:roles`);superadmin = 全部平台级(随闭集自动增长)。加平台级 `Perm` 时想清楚:平台管理员该不该有?不该 → 加进 `SUPERADMIN_ONLY`。
- **superadmin 只由 seed 声明**:任何接口授出 / 去掉它 → 403(账号接口,`assert_superadmin_untouched`;持 `platform:roles` 也不行);组织成员接口里它不是组织角色 → 422。角色目录(`GET /admin/auth/roles`)永不列它;没有 `platform:roles` 的调用者目录为空。seed 声明给多个账号、或库里已有别的账号持有 → 启动 / seed 报错。
- **防接管**(最重要):对**目标账号持有任一平台角色**的写操作 —— 账号接口(改信息 / 改资料 / 改角色 / 重置密码 / 删除)、平台成员接口(改角色 / 移出)、组织内成员接口(改角色 / 移出)—— 都要 `platform:roles`:`Policy::require_platform_role_authority(actor, scope, target_raw_roles)`;不在 users 模块的 handler 经组合根 `AppState::guard_platform_account`。
  - 目标角色用 **`user_roles` 原始名**(`raw_role_names`),**闭集外的名字算平台角色**(`holds_platform_role`,fail-closed);别用 `AdminUserView.roles`(lossy 读模型,脏数据会让闸失明)。
  - 组织内接口**先确认是本租户成员再判**(别的租户的人仍 404,不借 403 泄露他持平台角色);组织内「按用户名加成员」也判(加进来就移不走);平台 PUT 成员只在「已是成员 = 改角色」时判,平台管理员把人加进新组织不算动他。
  - 成员视图带 `holds_platform_role`(同口径,批量算、不逐个查),前端据此隐藏按钮。
  - **启动检查**:持 superadmin 的存活账号 > 1 → idm 进程拒绝启动(`seed::ensure_single_superadmin`;接口撤不掉 superadmin,存量多余的只能按 `scripts/prod/README.md` 手工清)。
  - 这道闸看目标数据,是 handler 里的条件闸,**不进 `op_perms` / OpenAPI security**(文档只在 403 描述里写)。前端按 `/permissions/me` 里有没有 `platform:roles` 隐藏对应按钮,后端兜底 403。
- 平台权限**不穿透**组织数据:平台管理员要看某组织的业务数据,仍得先成为该组织成员(作用域规则不变)。

## 多权限(AND / OR)

- enforcement:`policy.require_all(&user.0, &scope.0, &[A, B])`(缺一 403)/ `require_any(...)`(任一过,全败 403)——都经 `require_scoped`,role ∩ scope 与 implies 语义不变
- 文档:`OP_PERMS` 用 `PermReq::All(&[A, B])`(单 requirement 多 scope = OpenAPI AND)/ `PermReq::Any(&[A, B])`(多 requirement 各一 scope = OR);单权限 = `All` 单元素特例
- 探针免写:openapi_authz 自动钉 AND(去任一成员必 403)与 OR(每支单独必过)——加多权限端点只需表条目 + handler 同步
- 何时用:AND = 复合能力操作(样板 `purge_preview`:读+删的删除预检);OR = 多来路(样板 `widget_overview`:普通读权 `widgets:read` 或本组织成员管理员 `members:admin` —— 两支都是租户级,租户数据接口不混平台级权限)
- admin 组注意:组注入把后台准入(`admin:login` 或任一平台级权限,OR)与每个 requirement 做积,再去掉被蕴含的支 —— 本身要平台级权限的 op 就只剩它自己
