---
name: closed-enums
description: Use when adding or changing an API-facing (ToSchema) field that only ever takes values from a small fixed set (status / event type / channel / outcome / reason code) — decide String vs Rust enum, to keep the generated frontend union closed and eliminate unchecked `as` casts / frontend type drift.
---

# Closed enums (kill frontend type drift at the source)

The non-obvious **judgment**: a field with a **known, finite** set of string values that is reachable through `#[derive(ToSchema)]` (i.e. anything that ends up in `src/generated/api-types.d.ts` on the frontend after `pnpm generate`) must be a Rust **enum**, never a bare `String`. Mechanics: copy `AuthEventType` / `AuthChannel` / `AuthOutcome` / `FailureReason` (`features/auth_audit/types.rs`).

## bare `String` across the API boundary is not "flexible", it's a landmine

Rust `String` → OpenAPI `string` → TS `string`. The frontend gets zero compiler signal, so every consumer either (a) does an unchecked `row.field as SomeUnion` — the exact bug class that crashed `TapeRow` when `event_type` grew an `auth.` prefix nobody told the frontend union about — or (b) leaves it as raw `string` and loses exhaustiveness on any `Record<T, X>` lookup table (labels/icons/tone maps silently return `undefined` for a value they don't recognize). Both fail **silently**; both are exactly what happened before this fix.

## the enum recipe (copy this shape verbatim)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum AuthOutcome {
    #[serde(rename = "success")] #[sqlx(rename = "success")] Success,
    #[serde(rename = "failure")] #[sqlx(rename = "failure")] Failure,
}
```

Every variant renames to the **exact currently-stored string** — this is a strictness change, never a value/migration change. Add `FromStr` if the in-memory repo impl needs to parse a raw `String` back into the enum (mirrors `AuthEventType::FromStr`).

## no `#[serde(other)]` catch-all — by default

Justified only when the column has **one writer** (our own emit code, same binary as the reader) — no version-skew scenario exists, so an unknown value literally cannot occur. Add a catch-all **only** if a genuine multi-writer / rolling-deploy skew risk exists (independent services, or old+new binaries reading the same column mid-deploy) — and comment the reasoning inline if you do. Don't add one "just in case."

## read model gets the enum; write model can stay `String`

Precedent: `NewAuthEvent` (write side, fed from an internal NATS/JSON message already deserialized once) stays `String`; `AuthEventRow` / `AuthStats.*` (the `ToSchema` surface that actually becomes the generated frontend type) gets the enum. The strictness has to live at the boundary that generates the contract — don't bother enum-ifying a purely-internal intermediate that never reaches `ToSchema`.

## frontend: import, never redeclare

`types.ts` re-exports the generated union (`export type { AuthEventType } from '#/generated/api-types'`) as the single source of truth — no parallel hand-written local union. Any `Record<TheEnum, X>` (labels/icons/tone maps) then becomes **exhaustive**: adding a backend variant without updating the frontend map is a compile error, not a silent runtime `undefined`.

## Red flags

- a `ToSchema` struct field typed `String` / `Option<String>` that only ever holds one of a handful of known literals → make it an enum
- frontend doing `row.field as SomeUnion` on anything backed by a generated `string` → stop, enum-ify the backend field instead
- adding `#[serde(other)]` without a documented multi-writer/version-skew reason → probably wrong, remove it
- a hand-written union in frontend `types.ts` that duplicates something already `ToSchema`-exposed → replace with the generated import
