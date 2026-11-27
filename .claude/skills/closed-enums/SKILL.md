---
name: closed-enums
description: Use when adding or changing an API-facing (ToSchema) field that only ever takes values from a small fixed set (status / event type / channel / outcome / reason code) — decide String vs Rust enum, to keep the generated frontend union closed and eliminate unchecked `as` casts / frontend type drift.
---

# Closed enums (kill frontend type drift at the source)

The non-obvious **judgment**: a field with a **known, finite** set of string values that is reachable through `#[derive(ToSchema)]` (i.e. anything that ends up in `src/generated/api-types.d.ts` on the frontend after `pnpm generate`) must be a Rust **enum**, never a bare `String`. Mechanics: copy `AuthEventType` / `AuthChannel` / `AuthOutcome` / `FailureReason` (core `crates/core/src/features/auth_audit/model.rs`, schema markers in `src/features/auth_audit/adapters/http/dto.rs`, PG parsing in `.../adapters/pg_auth_event_repo.rs`).

## bare `String` across the API boundary is not "flexible", it's a landmine

Rust `String` → OpenAPI `string` → TS `string`. The frontend gets zero compiler signal, so every consumer either (a) does an unchecked `row.field as SomeUnion` — the exact bug class that crashed `TapeRow` when `event_type` grew an `auth.` prefix nobody told the frontend union about — or (b) leaves it as raw `string` and loses exhaustiveness on any `Record<T, X>` lookup table (labels/icons/tone maps silently return `undefined` for a value they don't recognize). Both fail **silently**; both are exactly what happened before this fix.

## the enum recipe (copy this shape verbatim)

The enum is a **domain** type, so it lives in the core crate (`crates/core/.../model.rs`) and derives **serde only** — no `ToSchema`, no `sqlx::Type` (the core crate has no utoipa / sqlx dependency at all). Because the enum is now a *foreign* type to the main crate, the orphan rule forbids `impl ToSchema for AuthOutcome` there — the macro generates a local **schema marker type** instead, and DTO fields point at it with `value_type`:

```rust
// model.rs (core)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthOutcome {
    #[serde(rename = "success")] Success,
    #[serde(rename = "failure")] Failure,
}
impl AuthOutcome {
    pub const ALL: [AuthOutcome; 2] = [AuthOutcome::Success, AuthOutcome::Failure]; // add new variants here
    pub fn as_str(self) -> &'static str { /* … */ }
}
impl std::str::FromStr for AuthOutcome { /* look up in ALL by as_str */ }

// adapters/http/dto.rs — marker type AuthOutcomeSchema, schema name "AuthOutcome", values from serde (cannot drift)
crate::closed_enum_to_schema!(AuthOutcomeSchema => AuthOutcome, AuthOutcome::ALL, "认证结果闭集");

#[derive(Serialize, ToSchema)]
pub struct AuthEventRow {
    #[schema(value_type = AuthOutcomeSchema)]          // response / request body field
    pub outcome: AuthOutcome,
}
#[derive(Deserialize, IntoParams)]
pub struct AuthEventFilter {
    #[param(value_type = Option<AuthOutcomeSchema>)]   // query parameter
    pub outcome: Option<AuthOutcome>,
}

// adapters/pg_auth_event_repo.rs — the row reads the column as String, TryFrom parses it via FromStr
outcome: r.outcome.parse().map_err(bad_closed_value)?,
```

Every variant renames to the **exact currently-stored string** — this is a strictness change, never a value/migration change. A wire round-trip test (serde ↔ `as_str` ↔ `FromStr` over `ALL`) keeps the three in sync.

## no `#[serde(other)]` catch-all — by default

Justified only when the column has **one writer** (our own emit code, same binary as the reader) — no version-skew scenario exists, so an unknown value literally cannot occur. Add a catch-all **only** if a genuine multi-writer / rolling-deploy skew risk exists (independent services, or old+new binaries reading the same column mid-deploy) — and comment the reasoning inline if you do. Don't add one "just in case."

## read model gets the enum; write model can stay `String`

Precedent: `NewAuthEvent` (write side, fed from an internal NATS/JSON message already deserialized once) stays `String`; `AuthEventRow` / `AuthStats.*` (the surface whose HTTP DTO / schema actually becomes the generated frontend type) gets the enum. The strictness has to live at the boundary that generates the contract — don't bother enum-ifying a purely-internal intermediate that never reaches `ToSchema`.

## frontend: import, never redeclare

`types.ts` re-exports the generated union (`export type { AuthEventType } from '#/generated/api-types'`) as the single source of truth — no parallel hand-written local union. Any `Record<TheEnum, X>` (labels/icons/tone maps) then becomes **exhaustive**: adding a backend variant without updating the frontend map is a compile error, not a silent runtime `undefined`.

## mapping a dependency's `#[non_exhaustive]` enum into a closed enum / error

idm / content are separate crates and mark their public enums `#[non_exhaustive]` (`IdmError`, `ContentError`, `CredentialFailure`, …), so a `match` on them **must** have a wildcard arm — and that arm only ever fires after a library upgrade adds a variant. Google's rule "Don't omit patterns on `non_exhaustive` enums when matching" decides the shape:

- **list every variant that exists today explicitly**, even ones that map to the same value as the wildcard — never let `_` silently absorb a known variant (adding a variant upstream must not change how today's variants are treated, and a reviewer must see the full current mapping in one place);
- the **wildcard arm only covers future variants**, and says so in a comment citing the rule;
- the wildcard must **not be silent**:
  - error enums → map to the internal error (HTTP **500**, `ErrorBody` without details, original error only in the log). Precedent: `From<IdmError>` / `From<ContentError>` for `AppError` in `crates/core/src/kernel/app_error.rs`;
  - closed value enums with no "other" variant (audit reason codes …) → map to the most generic existing value so the record still lands and the OpenAPI union stays unchanged, **and** `tracing::warn!` with the unknown value (WARN goes into `ops.log_record` via the monitor layer) so the next upgrade adds a proper value. Precedent: `From<&CredentialFailure> for FailureReason` in `crates/core/src/features/auth_audit/model.rs`;
  - don't add an "unknown"/"other" variant to the API-facing enum just for this — that widens the generated frontend union for a case that should never reach production;
- test every known variant's mapping (the wildcard itself can't be constructed in tests; it's guarded by review).

## Red flags

- a `ToSchema` struct field typed `String` / `Option<String>` that only ever holds one of a handful of known literals → make it an enum
- frontend doing `row.field as SomeUnion` on anything backed by a generated `string` → stop, enum-ify the backend field instead
- adding `#[serde(other)]` without a documented multi-writer/version-skew reason → probably wrong, remove it
- a hand-written union in frontend `types.ts` that duplicates something already `ToSchema`-exposed → replace with the generated import
