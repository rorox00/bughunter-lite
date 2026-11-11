# GraphQL attack reference

Map the schema, then test whether authorization is enforced per field/object.
All via `transport.ScopedSession`; compare identities with
`replay.cross_session`/`authz_signal` and bodies with `diffr.diff`. Read-only:
prove reachability; never run destructive mutations or actually DoS prod.

## Introspection (schema dump)
- Standard introspection query (`__schema { types { name fields { name
  args { name } type { name } } } queryType { ... } mutationType { ... } }`).
- If blocked, try: GET vs POST, `application/graphql` content-type, field
  suggestions in error messages ("Did you mean ...?"), and operations recovered
  from the JS bundle via `js-analyze`.
- Note every field/resolver that takes an id or returns an object — that's the
  authz attack surface.

## Field-level authz (BOLA / BFLA)
- Request a victim object directly, then through the generic `node(id:)`
  resolver (Relay global ids are base64 `Type:id` — decode/re-encode; see
  hunt-idor's `id-formats.md`).
- **Nested traversal**: reach a protected object as a nested field of one you
  own (`me { org { members { email ssn } } }`).
- **BFLA**: call an admin-only query/mutation as a low-priv user.
- Confirm REAL only when attacker gets the victim's data AND anon does not;
  a `null` may be authz OR empty — disambiguate with `diffr.diff` vs your own
  object.

## Batching & alias abuse
- **Aliases**: `a: user(id:1){email} b: user(id:2){email} ...` enumerates many
  ids in one request and often bypasses per-request rate limits (brute of
  OTP/login/coupons → chain to the relevant hunt skill).
- **Query batching**: an array of operations in one HTTP request for the same
  amplification. Demonstrate the multiplier read-only.

## Denial-of-service vectors (note, don't fire)
- Deeply nested/recursive selections, or circular fragments, inflate resolver
  cost; large `first:`/pagination values; alias multiplication.
- Record the depth/shape and that no depth/cost limit exists;
  `proof_note:"DoS vector, not exercised"` — never actually degrade prod.

## Mutations
- Treat object-taking mutations as BOLA: prove the id/arg is reachable and
  unauthorized read-only; do not mutate prod data
  (`proof_note:"intrusive, NOT performed"`).
