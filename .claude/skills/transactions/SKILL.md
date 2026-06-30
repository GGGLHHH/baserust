---
name: transactions
description: Use when adding a repo operation that writes more than once and must be all-or-nothing (atomic / transactional / rollback), or deciding how a transaction crosses the pluggable repo trait.
---

# Transactions (atomic multi-write through the pluggable repo)

The non-obvious **judgment** — stated so you get it right *even before* reading the sample. Mechanics: **copy `create_with_tags`** (`features/widget/repo/`) — the live template (PG `begin/commit`, memory lock).

## the atomic unit is ONE trait method — never thread a transaction

Model the whole atomic operation as a single coarse-grained method on the repo trait (`create_with_tags`, `reassign`, `create_order_with_lines`). The transaction boundary lives **inside each impl**.

**Never** put `sqlx::Transaction` / a `begin()` / a `Box<dyn TxHandle>` / a generic executor in the trait signature, and **never** orchestrate `tx.insert_a(); tx.insert_b(); tx.commit()` from the service. That:
- **breaks object-safety** — `sqlx::Executor` isn't dyn-safe; a `dyn TxHandle` holding a `MutexGuard` across `.await` is `!Send` (kills the `Send + Sync` async-trait bound), else it forces a buffer-and-replay tx engine;
- **leaks sqlx** into the shared trait (violates "decouple repo, not sqlx");
- has **nothing the in-memory impl can hand out**.

## the two impls

| | Postgres | in-memory |
|---|---|---|
| boundary | `let mut tx = pool.begin()?; … .execute(&mut *tx) … tx.commit()?` | one `store.lock()` |
| rollback | any `?` drops `tx` → auto `ROLLBACK` | **validate BEFORE any mutation** → an early `return Err` leaves the store untouched |

**Memory discipline (load-bearing): validate-before-mutate.** Run every check first; write only once all pass. `mutate-then-fail` leaves half-written rows → loses atomicity and drifts from PG. Use one `now_utc()` for all rows in the unit (mirrors PG defaults/trigger).

## conformance pins what a single statement can't show

Assert the **all-or-nothing** invariant: a failing call returns its error **AND leaves the row set unchanged** (PG inserts the parent then rolls it back; memory never inserts it). Without this assertion the atomicity is untested.

## limit — when this is NOT enough

Covers **aggregate-internal** atomicity: multiple writes within ONE repo / ONE pool. It does **not** compose a transaction across multiple repo methods or repos — each `&self` method opens and closes its own tx. Cross-schema / cross-pool (app + idm) atomicity is physically impossible → saga / outbox / eventual consistency. Cross-request lost-update is a `version` column (optimistic lock), not this.

## Red flags
- `&mut Transaction` / `begin()` / `TxHandle` / executor in a repo trait method → make it one intent method, tx inside the impl
- service doing `tx.x(); tx.y(); commit()` → push it into a single repo method
- memory impl mutating before all validation → validate first (else it isn't atomic)
