---
name: adding-a-feature
description: Use when adding a new business feature module (a new resource like user/order/post) to the baserust scaffold under src/features/, or wiring a new feature's routes/state/migrations into the app.
---

# Adding a feature module to baserust

## Overview

baserust is vertical-slice: each business domain is one `src/features/<name>/` dir, thin-layered `routes → service → repo(trait) → types`. **Copy the `widget` module** — it is the canonical sample. This skill is NOT a re-teaching of the layering (read `widget/` for that); it's the **wiring checklist + the non-obvious gotchas that copying widget won't make obvious**.

## Files to create

```
src/features/<name>/
  mod.rs                 router() + `pub use` repo/service
  types.rs               <Name> (FromRow+ToSchema) + Create<Name> (Deserialize+Validate)
  service.rs             <Name>Service(Arc<dyn <Name>Repo>) + #[cfg(test)] tests
  routes.rs              #[utoipa::path] handlers (thin)
  repo/
    mod.rs               <Name>Repo trait + #[derive(Iden)] enum + COLS const
    memory.rs            In-memory impl (default, test-friendly)
    postgres.rs          sea-query impl + base_select()
migrations/app/000N_create_<name>s.{up,down}.sql
tests/<name>_api.rs      oneshot integration tests (optional but expected)
```

## Wiring (4 edits — all required, easy to half-finish)

1. `src/features/mod.rs` — `pub mod <name>;`
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
| **`COLS` order / no `deleted_at`** | Column order must match the `<Name>` FromRow field order; `COLS` excludes `deleted_at` (DTO never exposes it) |
| **Route path** | Write `path = "/<name>s"` — the `/api/v1/<group>` prefix is added by `nest` (group = public/frontend/admin, see `router.rs`; default business CRUD belongs in `frontend`), don't repeat it |
| **Reuse the pool** | In `AppState::new`'s `Some(url)` arm, `connect_pool` once and `pool.clone()` into each repo (PgPool is Arc-cheap) — don't connect per feature |

## API style (project convention — NOT a per-feature choice)

RESTful、资源导向,全项目统一,新端点照做、别逐 feature 重选:

- **写操作用 `PUT` 全量替换,不用 `PATCH`**。更新端点收资源的**完整表示**:必填字段必传,可选字段给值=设、给 null 或缺=清空。请求 DTO 别为"部分更新"把字段全 `Option`(那是 PATCH 语义)。范例:idm `PUT /auth/me`(`UpdateMeRequest { username: String, email: Option<String> }`)→ repo `update(id, username: &str, email: Option<&str>, by)` 全量替换、替换 email 重置 email_verified。
- 标准动词:`GET`(取/列)、`POST`(建→201)、`PUT`(全量更新)、`DELETE`(删→204)。path 用复数资源名(`/widgets`),`/api/v1/<group>` 由 nest 加(组见 `router.rs`;默认业务 CRUD 归 `frontend` 组)、别重复。

## Decisions to make (don't default silently)

- **Audit/soft-delete fields**: keep the 5 base fields (`created_by/created_at/updated_by/updated_at/deleted_at`) + `base_select()` filtering `deleted_at IS NULL`, to stay consistent with widget. Drop them only with a deliberate reason.
- **Unique constraint → 409**: add the unique index in a **migration** (partial `WHERE deleted_at IS NULL` if you soft-delete, so deleted rows free the value — see `widgets_name_unique_alive` in `0001`). Then mirror `widget`'s `map_db_err` (`repo/postgres.rs`): **both `create` AND `update`** end with `.map_err(map_db_err)` so a `23505` unique violation becomes `AppError::Conflict`(409), not `Internal`(500). **Mirror the check in the in-memory repo too** (reject a duplicate live name on create/update with `Conflict`) — `widget_repo_conformance` pins memory↔PG parity and will go red if you skip it. Mark `(status = 409, body = ErrorBody)` on the create/update `#[utoipa::path]`. (Never edit an already-applied migration to add the index — append a new one, or `just migrate-app-revert` → edit → `migrate-app` locally.)
- **Reuse infra**: pagination (`PageQuery::resolve` → `Page<T>`), `AuditContext` (`ctx.audit_id()` → created_by/updated_by), custom `extract::{Json,Path,Query}`, `AppError`. Never re-implement these per feature.

## Verify

`just check && just test && just lint` (clippy is `-D warnings` — zero warnings required). Integration test pattern: copy `tests/widget_api.rs` (`test_app()` builds an in-memory `AppState`, `oneshot` hits real endpoints, no DB).
