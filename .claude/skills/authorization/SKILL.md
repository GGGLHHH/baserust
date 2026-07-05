---
name: authorization
description: Use when adding or changing an endpoint that needs auth, deciding who can call what, reasoning about why an endpoint returns 403 vs 404, how permissions appear in the OpenAPI docs, or whether to gate on a role.
---

# Authorization (app-owned)

The non-obvious **judgment** — stated so you get the critical calls right *even before* digging through the code. Mechanics (how to wire a gate) = **copy `widget`**: it has a sample of every shape (public / authenticated / perm-gated / ownership / superadmin-only).

## perm is the only currency — never gate on a role

No `if role == "superadmin"` / `roles.contains(...)` in a handler. Effective auth = `role perms ∩ token scope`, so a raw role-string check **ignores `TokenScope`** → a deliberately down-scoped token (PAT / 3rd-party) sails through your most dangerous endpoint. "Only role X" = gate a `Perm` only X is granted in `seed.toml`. Note `Perm::UsersAdmin` is **superadmin-only** — gating on it locks regular *admins* out; for an admin-able action, grant a perm to admin too (or add a dedicated `Perm`).

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
| which perms exist | `Perm` enum — `infra/authz.rs` |
| endpoint → perm (**docs**) | `infra/op_perms.rs` — add one row |
| endpoint → perm (**enforce**) | the handler's `require_scoped` |
| role → perms | `seed.toml` |

Doc `security` is **injected from `op_perms`** after `split_for_parts` — **never hand-write `security(("oauth2"=...))` in `#[utoipa::path]`**; `every_operation_classified` fail-closes on an unclassified op.

## Red flags
- `if role == ...` / `roles.contains(...)` → gate a perm
- 403 for "not yours" → should be 404
- hand-written `security(("oauth2"=...))` in a path macro → add an `op_perms` row
- ownership rule going into OpenAPI `security` → it can't live there

## 多权限(AND / OR)

- enforcement:`policy.require_all(&user.0, &scope.0, &[A, B])`(缺一 403)/ `require_any(...)`(任一过,全败 403)——都经 `require_scoped`,role ∩ scope 与 implies 语义不变
- 文档:`OP_PERMS` 用 `PermReq::All(&[A, B])`(单 requirement 多 scope = OpenAPI AND)/ `PermReq::Any(&[A, B])`(多 requirement 各一 scope = OR);单权限 = `All` 单元素特例
- 探针免写:openapi_authz 自动钉 AND(去任一成员必 403)与 OR(每支单独必过)——加多权限端点只需表条目 + handler 同步
- 何时用:AND = 复合能力操作(样板 `purge_preview`:读+删的删除预检);OR = 多来路(样板 `widget_overview`:普通读权或管理员)
- admin 组注意:组注入会把 `users:admin` 并进**每个** requirement(含 OR 每支)
