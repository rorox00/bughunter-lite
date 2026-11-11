---
name: hunt-idor
description: Broken object-level authorization (IDOR / BOLA / BOPLA) - horizontal and cross-tenant access to another same-level user's objects. Use when a request carries an object reference (path/query/body/header) you can swap. Token-swap vertical privesc lives in hunt-auth-bypass/hunt-jwt, not here. Triggers - idor, bola, bopla, object reference, cross-tenant, horizontal privesc, swap id.
---

# hunt-idor
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Object refs you control: `/users/{id}`, `?id=`, `?account_id=`, `?org_id=`, `?workspace_id=`, `?ids[]=`, `order_id`, UUIDs, `node(id:)`, multipart `ownerId`, `{"user_id":...}`. Priority: sequential ints and multi-tenant ids; UUIDs only if they leak/are derivable.

## Method
1. Two SAME-role identities: `state.set_session("victim", headers=/cookies=)` and `("attacker", ...)` (anon is added automatically by `cross_session`).
2. CLEAN the request: send with the **attacker's own** cookies/CSRF; strip any victim anti-replay token from url/body — otherwise false positive.
3. Read replay: `m = replay.cross_session(http, url, {"victim":A, "attacker":B})`; `replay.authz_signal(m,"victim","attacker")["likely_broken_authz"]` — REAL only if attacker gets victim's data AND `m["anon"]` does NOT.
4. BOPLA property check: inspect privilege fields (`role`, `tenant_id`, `is_admin`); test non-destructive mass-assignment on PATCH/PUT.
5. Mutation reachability: read-only — prove a write is reachable & unauthorized WITHOUT mutating prod; else `proof_note:"intrusive, NOT performed"`.
6. Enumerate: int ±1/±100 or `toolbridge.ffuf`; UUID only if discoverable. If a swap returns 403/404, work `references/idor-tricks.md` before giving up. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- `m["anon"]` returns the same payload → it's **public**, not IDOR.
- Attacker gets 200 but an **empty body / error shape / only his own data** (confirm with `diffr.diff`).
- UUID is unguessable and **never leaked/derivable** (see `references/id-formats.md`).
- No boundary actually crossed (same user, same tenant, same role).

## Done
Non-zero evidence bundle: victim + attacker cross-session requests + body diff. `confirmed`, `severity`, `proof_note`, and one impact line stating scope (e.g. "read any tenant's invoices via sequential-int enumeration — N users").

## references/
`idor-tricks.md` (angles when a swap is blocked), `id-formats.md` (decode/derive ids), `graphql-idor.md` (node/global-id BOLA).
