---
name: hunt-graphql
description: GraphQL authorization & exposure flaws - schema disclosure via introspection, missing field-level authz (BOLA/BFLA over node/aliases), batching/alias abuse, and nested-query DoS. Use when you see /graphql, /api/graphql, or an Apollo/Relay endpoint. Triggers - graphql, introspection, apollo, relay, graphql idor, field authz, query batching. Related - hunt-idor.
---

# hunt-graphql
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
A GraphQL endpoint: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, Apollo/Relay servers, a `query`/`mutation` POST body. GraphiQL/playground exposed.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. **Introspection**: send the introspection query (see `references/graphql.md`); a full schema dump maps every type, field, and id-taking resolver. If disabled, mine operations from the JS bundle (`js-analyze`).
3. **Field-level authz (BOLA/BFLA)**: as the attacker identity, request another user's object — directly, via `node(id:)`, via nested traversal, or via alias batching. Confirm cross-user access with `state.set_session` + `replay.cross_session`/`authz_signal` (REAL only if attacker gets victim data AND anon does not). Overlaps `hunt-idor`/graphql-idor.
4. **Batching / alias abuse**: many aliased queries or a batched operation array in one request → rate-limit/brute bypass; demonstrate the amplification read-only.
5. **Nested-query DoS**: deeply nested/recursive selections inflate cost. Note the vector and depth; do NOT actually DoS prod — `proof_note:"DoS vector, not exercised"`.
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- Introspection is **disabled** AND field-level authz is **enforced** (no cross-user/privileged field reachable).
- A field returns **only your own data** (null/filtered for the victim id — confirm with `diffr.diff`, not assumption).
- Introspection enabled but schema is **public/documented** with no sensitive field or authz gap (info-only, low at best).
- Batching allowed but rate-limited/costed with no real amplification.

## Done
Schema exposure that reveals sensitive/undocumented surface, OR cross-user / privileged field access (the victim's data via your session). Full operation(s) + identities. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "read any user's PII via node(id:) with no field authz").

## references/
`references/graphql.md` — introspection query, authz-bypass & graphql-idor patterns, batching/alias.
