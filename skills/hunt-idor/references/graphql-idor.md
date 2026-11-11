# graphql-idor — BOLA over GraphQL

GraphQL concentrates object access behind a single endpoint, which makes
object-level authz easy to miss. Same rule as always: attacker's own session,
attacker fetches victim's object, anon cannot. Route through
`transport.ScopedSession`; compare identities with `replay.cross_session` /
`authz_signal` and bodies with `diffr.diff`.

## Map the object surface
- Run introspection (if enabled) to list types, `node(id:)`/`node s`, and every
  field that takes an id or returns an object by reference.
- If introspection is disabled, mine queries from the JS bundle
  (`js-analyze`) and from observed requests.

## Global id (Relay) decode
- `node(id: "...")` ids are usually base64 `Type:internalId`. Decode (see
  `id-formats.md`), substitute the victim's internal id, re-encode, and request
  via `node` — a classic BOLA bypass when the per-field resolver trusts `node`.

## Access angles
- **node() back-door**: an object protected on its typed query may be reachable
  through the generic `node(id:)` resolver.
- **Nested traversal**: reach a victim object as a nested field of an object you
  legitimately own (`me { organization { members { ssn } } }`-style).
- **Alias batching**: request many ids in one document via aliases
  (`a: order(id:1) b: order(id:2) ...`) to enumerate fast; also a rate-limit
  bypass.
- **Query batching**: send an array of operations in one HTTP request.
- **Mutation BOLA**: a mutation that takes an object id — prove reachability
  read-only; do not mutate prod (`proof_note:"intrusive, NOT performed"`).

## Confirm, don't assume
- A field returning `null` for the victim id may be authz OR just empty — use
  `diffr.diff` against your own object to tell "forbidden/filtered" from
  "actually returned victim data".
