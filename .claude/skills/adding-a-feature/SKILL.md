---
name: adding-a-feature
description: Use when adding a new business feature module (a new resource like user/order/post) to the baserust scaffold under src/features/, or wiring a new feature's routes/state/migrations into the app.
---

# Adding a feature module to baserust

## Overview

baserust is vertical-slice: each business domain is one `src/features/<name>/` dir, hexagonal (ports & adapters): a pure core (`model` / `ports` / `service`) plus `adapters/` (HTTP, memory, Postgres). **Copy the `widget` module** — it is the canonical sample. This skill is NOT a re-teaching of the layering (read `widget/` for that); it's the **wiring checklist + the non-obvious gotchas that copying widget won't make obvious**.

## Files to create

```
crates/core/src/features/<name>/       ── core crate `baserust-core` (no axum / utoipa / sqlx / sea-query in its Cargo.toml at all)
  mod.rs                 `pub mod` + `pub use` of the core surface (service, ports, model, memory types)
  model.rs               <Name> domain struct + Create<Name>/Update<Name> (Deserialize + garde Validate) + sort field enum
  ports.rs               <Name>Repo trait (+ any narrow ports to other modules, e.g. UserDirectory)
  service.rs             <Name>Service(Arc<dyn <Name>Repo>): takes PageParams / domain inputs, returns kernel Page<T> + #[cfg(test)] tests on the memory repo
  memory.rs              In-memory impl (default runtime impl + the core tests' fake)
crates/core/src/features/mod.rs        add `pub mod <name>;`

src/features/<name>/                   ── main crate: adapters only
  mod.rs                 `pub use baserust_core::features::<name>::*;` + `pub mod adapters;` + adapter re-exports
  adapters/mod.rs        `pub mod http; pub mod postgres;` + `pub use baserust_core::features::<name>::memory;`
  adapters/http/dto.rs   wire DTOs (Serialize/Deserialize + ToSchema, keep stable names) + From/Into domain
  adapters/http/routes.rs #[utoipa::path] handlers returning `Result<_, ApiError>` (thin: extract → DTO.into() → service → Dto::from)
  adapters/http/mod.rs   router()s (OpenApiRouter + routes!)
  adapters/postgres.rs   sea-query impl: #[derive(Iden)] enum + COLS + <Name>Row (FromRow) → <Name> + base_select() + map_db_err;
                         every trait method gets #[tracing::instrument(name = "pg.<name>s.<fn>", skip_all)] (feeds the admin monitoring page; see `observability` skill)
migrations/app/000N_create_<name>s.{up,down}.sql   (tenant_id + CHECK not-nil + (tenant_id, …) indexes + ENABLE/FORCE RLS + policy — see below)
tests/http_<name>.rs   black-box HTTP acceptance (real port + reqwest; header `//! covers: METHOD /path` for every endpoint)
```

## Wiring (4 edits — all required, easy to half-finish)

1. `crates/core/src/features/mod.rs` **and** `src/features/mod.rs` — `pub mod <name>;` (core + adapters)
2. `src/app/state.rs` — add `pub <name>s: <Name>Service` field; wire it in `AppState::new`
3. `src/app/router.rs` — mount the routes (see gotcha #1)
4. `src/infra/openapi.rs` — add `(name = "<name>s", ...)` to `tags(...)`

## Gotchas (these bite — baseline agents trip here)

| Gotcha | Do this |
|---|---|
| **Two `.nest(...)` on the same prefix panics** (axum rejects duplicate prefix) | merge your router into its **group** router in `router.rs` (`public`/`frontend`/`admin` — see "Route path" below for which); each group is still nested exactly once |
| **Adding an AppState field breaks every test** | `AppState` is built by-struct in each `tests/*_api.rs` `test_app()`; add the new field there too, or the whole crate fails to compile |
| **`just migrate-add` makes a timestamp prefix** | Hand-write `000N_create_<name>s.{up,down}.sql` to keep the sequential `000N` convention |
| **`set_updated_at_utc()` is shared** | It's created by `0001`. New migration only `create trigger ... execute function set_updated_at_utc();`. down: drop the trigger, **never** drop the function |
| **`COLS` order / no `deleted_at`** | Column order must match the `<Name>Row` FromRow field order (in `adapters/postgres.rs`); `COLS` excludes `deleted_at` (DTO never exposes it) |
| **Route path** | Write `path = "/<name>s"` — the `/api/v1/<group>` prefix is added by `nest` (group = public/frontend/admin, see `router.rs`; default business CRUD belongs in `frontend`), don't repeat it |
| **Reuse the pool** | In `AppState::new`'s `Some(url)` arm, `connect_pool` once and `pool.clone()` into each repo (PgPool is Arc-cheap) — don't connect per feature |

## Multi-tenancy (mandatory — every business feature is tenant data unless proven global)

Copy `widget` again — it is the tenant-isolated sample. The checklist (each item is guarded by a test, so skipping one goes red somewhere):

| Layer | Do this | Guard |
|---|---|---|
| **core (ports / service / memory)** | Every repo + service method takes `tenant: TenantId` (`kernel::tenant::TenantId`, never a raw `Uuid`; nil can't be constructed). Memory impl stores the tenant on each row and filters by it on **every** read/write — a row of another tenant behaves as missing (`NotFound`). Uniqueness is per tenant. | `<name>_repo_conformance` (memory ↔ PG) |
| **migration** | `tenant_id uuid not null` + `check (tenant_id <> '00000000-0000-0000-0000-000000000000')`; unique / list / keyset indexes **lead with `tenant_id`**; child tables carry their own `tenant_id` (policies don't sub-query the parent); `alter table … enable row level security; alter table … force row level security; create policy tenant_isolation on … using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (<same>)`. Template: `migrations/app/0006_widget_tenancy.up.sql`. Adding tenancy to a table that already has rows → **backfill before enabling RLS**. | `tests/rls_audit.rs` (`just test-pg`) fails for any table neither isolated nor in `GLOBAL_TABLES` |
| **PG adapter** | Each method: `let mut tx = tenant_tx(&self.pool, tenant).await?` (`infra::pg::tenant_tx` = `begin` + transaction-local `set_config('app.tenant_id', …, true)`), run the SQL with an explicit `tenant_id = $1` too (index + first line of defence; RLS is the second), `tx.commit()`. **Never** a session-level `SET`, never the `*_system_pool` for request paths. | rls_audit (runtime role is not owner, no BYPASSRLS) |
| **HTTP handler** | Take `CurrentTenant(tenant): CurrentTenant` (`infra::http::audit`): tenant comes **only** from the token (403 `tenant_required` when absent — never fall back to the default tenant). Don't accept `tenant_id` in body / query. Gate with **tenant-scoped** perms (`Perm::scope()` → `Tenant`), also for admin-group endpoints. | `openapi_authz`, `perm_scopes_cover_all_variants` |
| **events / SSE** | Every event variant carries `tenant_id`; the SSE handler skips frames whose `event.tenant_id() != tenant` (`continue`, don't end the stream). Outbox payloads include `tenant_id` (copied onto the envelope). | `sse_does_not_leak_other_tenant_events` pattern |
| **black-box tests** (`tests/http_<name>.rs`) | Copy widget's cross-tenant set: other tenant's id → **404** for get/update/delete; list shows only the current tenant; same unique value allowed in two tenants; SSE doesn't leak; endpoints without a current tenant → 403 `tenant_required`. | review — there is no automatic guard, so don't skip it |

Genuinely global data (dictionaries, per-account rather than per-organization data): no `tenant_id`, add `"<schema>.<table>"` to `GLOBAL_TABLES` in `tests/rls_audit.rs` with a comment why. Background jobs / projectors that must cross tenants use the `*_system_pool` (BYPASSRLS) — and must still write the right `tenant_id` per row.

## API style (project convention — NOT a per-feature choice)

RESTful、资源导向,全项目统一,新端点照做、别逐 feature 重选:

- **写操作用 `PUT` 全量替换,不用 `PATCH`**。更新端点收资源的**完整表示**:必填字段必传,可选字段给值=设、给 null 或缺=清空。请求 DTO 别为"部分更新"把字段全 `Option`(那是 PATCH 语义)。范例:idm `PUT /auth/me`(`UpdateMeRequest { username: String, email: Option<String> }`)→ repo `update(id, username: &str, email: Option<&str>, by)` 全量替换、替换 email 重置 email_verified。
- 标准动词:`GET`(取/列)、`POST`(建→201)、`PUT`(全量更新)、`DELETE`(删→204)。path 用复数资源名(`/widgets`),`/api/v1/<group>` 由 nest 加(组见 `router.rs`;默认业务 CRUD 归 `frontend` 组)、别重复。

## Decisions to make (don't default silently)

- **Audit/soft-delete fields**: keep the 5 base fields (`created_by/created_at/updated_by/updated_at/deleted_at`) + `base_select(tenant)` filtering `tenant_id = $1 AND deleted_at IS NULL`, to stay consistent with widget. Drop them only with a deliberate reason.
- **Unique constraint → 409**: add the unique index in a **migration** (partial `WHERE deleted_at IS NULL` if you soft-delete, so deleted rows free the value; tenant data leads with `tenant_id` so uniqueness is per tenant — see `widgets_name_unique_alive`, created in `0001`, made `(tenant_id, name)` in `0006`). Then mirror `widget`'s `map_db_err` (`adapters/postgres.rs`): **both `create` AND `update`** end with `.map_err(map_db_err)` so a `23505` unique violation becomes `AppError::Conflict`(409), not `Internal`(500). **Mirror the check in the in-memory repo too** (reject a duplicate live name **in the same tenant** on create/update with `Conflict`) — `widget_repo_conformance` pins memory↔PG parity and will go red if you skip it. Mark `(status = 409, body = ErrorBody)` on the create/update `#[utoipa::path]`. (Never edit an already-applied migration to add the index — append a new one, or `just migrate-app-revert` → edit → `migrate-app` locally.)
- **Reuse kernel / infra**: pagination (handler: `PageQuery::resolve()` → `kernel::pagination::PageParams` → service returns `kernel::pagination::Page<T>` → handler `infra::http::pagination::Page::from_core(page, Dto::from)`), `kernel::audit::AuditContext` (handler extracts it as `Audit(ctx): Audit`; `ctx.audit_id()` → created_by/updated_by), `infra::http::extract::{Json,Path,Query}`, `kernel::error::AppError` (services return it; handlers return `infra::http::error::ApiError`, `?` converts). Never re-implement these per feature.
- **Keep the core pure**: the compiler enforces it (the core crate simply has no web / DB deps); `tests/architecture.rs` additionally fails if the core Cargo.toml gains such a dependency, if a core module imports another feature, or if model/port/service code lands in the main crate. A closed enum the API exposes stays serde-only in `model.rs`; its OpenAPI schema is a marker type from `crate::closed_enum_to_schema!(XSchema => X, …)` in `adapters/http/dto.rs`, referenced with `#[schema(value_type = XSchema)]` (see `closed-enums` skill). Cross-module needs go through a port in `ports.rs`, adapted in `src/app/adapters/`.

## Verify

`just check && just test && just lint` (includes `tests/architecture.rs`) (clippy is `-D warnings` — zero warnings required), plus `just test-pg` against a test PG for the conformance + `rls_audit`. Acceptance tests: copy `tests/http_widget.rs` — `http_support::TestServer` starts the real composition root in memory mode on a random port, a reqwest session (cookies) hits real endpoints, no DB, no web-framework types in the test body. `http_coverage` fails until every endpoint in the spec appears in some file's `//! covers:` list; `openapi_snapshot` fails on any contract change (accept with `just openapi-snapshot-accept`).
