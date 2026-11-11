---
name: hunt-sqli
description: SQL injection - prove attacker control over a backend query (error/union, boolean, time, or out-of-band). Use when a param feeds search/filter/sort/id/where/login logic. Triggers - sqli, sql injection, union, boolean blind, time-based, order by, error-based.
---

# hunt-sqli
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Params that reach a query: `search`, `filter`, `sort`/`order`, `id`, `where`, `category`, `q`, login fields. Tells: DB error strings leaking on a quote, type-juggling (`id=1` vs `id=1e0`), `ORDER BY n` position changes, boolean-looking params.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Capture a baseline, then send a probe that changes query structure (quote, `' OR 1=1 --`, `ORDER BY N`, arithmetic `1` vs `1-0`). Compare with `diffr.diff(baseline, probe)` — look for status/length/row-count/error shifts, not input echo.
3. **Error/union first** when output reflects: a controlled column count / DB banner confirms fast and minimally.
4. **Blind**: boolean (true vs false payload → `diffr.diff` must flip deterministically) and time-based (a conditional delay → `elapsed_ms` delta beyond `diffr`'s `time_ms`). See `references/sqli-blind.md`.
5. **Out-of-band**: `oast.new_url("sqli")` injected into a DNS/HTTP exfil primitive, confirmed with `oast.poll(contains="sqli")` — the oracle for fully-blind cases.
6. Breadth: `toolbridge.nuclei` for templated detection. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The "error" is a generic 500/400 with **no injection control** (same error on benign input).
- A WAF/app **reflects your payload unchanged** with no DB interaction (no behavioral difference).
- The difference is just **input echo**, not query behavior (boolean true/false don't flip the response).
- Time delta is noise, not a deterministic, repeatable conditional delay.

## Done
Demonstrated data/boolean/time control with **minimal** proof — e.g. the DB version string, or one controlled boolean that flips on demand. Never dump real PII; stop at proof-of-control. Record request(s) + proof, `confirmed`, `severity`, `proof_note`, one impact line.

## references/
`references/sqli-blind.md` — boolean / time / second-order / out-of-band techniques (categories, not a payload dump).
