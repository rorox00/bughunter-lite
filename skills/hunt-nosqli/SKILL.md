---
name: hunt-nosqli
description: NoSQL injection (Mongo-style) - attacker-supplied query operators or JS alter a NoSQL query, bypassing auth or controlling the result set. Use on JSON auth/query params that reach a document store. Triggers - nosql injection, nosqli, mongo injection, operator injection, $ne, $gt, $where, auth bypass json.
---

# hunt-nosqli
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
JSON (or form) params that feed a Mongo-style backend: login (`{"user":...,"pass":...}`), search/filter, lookups by id. Tells: the param value is placed into a query object; the endpoint accepts JSON where you can send an object instead of a string.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. **Operator injection**: replace a scalar with a query operator object — `{"$ne":null}`, `{"$gt":""}`, `{"$regex":".*"}`, `{"$exists":true}`, `{"$in":[...]}`. On login, `{"user":{"$ne":null},"pass":{"$ne":null}}` or a known user + `{"pass":{"$gt":""}}` tests an always-true match.
3. **Confirm behavior change**: `diffr.diff(baseline, injected)` — a login that now succeeds, a filter that returns far more/all rows, or a boolean that flips deterministically (operator → true vs false). Input echo alone is not it.
4. **JS injection** where `$where`/`mapReduce`/`$function` eval user strings: a boolean/time expression confirms server-side evaluation (benign only; no destructive ops). Blind → use timing via `diffr`'s `time_ms`, or `oast` if a network primitive exists.
5. Prove control, not exfiltration: an auth bypass or a demonstrably attacker-controlled result set is enough — never dump real PII. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- Input is **coerced to a string** (operators arrive as literal text, no object parsed) — injection doesn't take.
- The query is **parameterized / schema-validated** (object operators rejected or ignored).
- **No behavior change** between benign and operator payloads (same result, same count).
- A 200 that returns only your own/empty data, not a boundary crossed or query controlled.

## Done
An auth bypass (logged in without valid creds) OR demonstrated query/result control (operator makes the query return attacker-chosen rows / an always-true match), with the exact JSON payload + the differing response. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "authentication bypass via {\"$ne\":null} on the login endpoint").
