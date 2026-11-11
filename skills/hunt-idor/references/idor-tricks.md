# IDOR tricks — angles when a straight swap is blocked

A victim-id swap that returns 401/403/404 is not a dead end. Work these angles
before giving up. Every attempt uses the **attacker's own** session via
`transport.ScopedSession` / `replay.cross_session`; the win is always
"attacker sees victim's object AND anon does not".

## Where the id lives
- Move the id between **path, query, body, and headers** (`X-User-Id`,
  `X-Account-Id`, `X-Tenant-Id`) — auth often checks only one location.
- Add the id **in a second place** while leaving the legit one (last-wins
  parsing may use yours).

## Parameter pollution & shape
- HTTP parameter pollution: `?id=self&id=victim` (and the reverse order).
- Wrap or unwrap: `id[]=victim`, `{"id":["victim"]}`, `{"id":{"id":victim}}`.
- Send both your id and the victim's; add `ids[]=` batch forms.

## Method & content-type
- Swap the method: `GET`↔`POST`, add `X-HTTP-Method-Override`.
- Change `Content-Type` (json↔form↔multipart) so a different, weaker handler
  parses the id.

## Encoding / format of the value
- URL-encode / double-encode separators; add trailing `.json`, `/`, `;`, `%00`.
- Case changes; swap int↔string; see `id-formats.md` to decode/derive the real
  value when it's opaque.

## Different doorway to the same object
- Try **sibling endpoints** for the same resource: export/report/print/download,
  `/v1` vs `/v2`, admin vs user API, GraphQL `node(id:)` (see `graphql-idor.md`).
- Object referenced indirectly (e.g. by slug, email, or a nested relation).

## Blind / side-channel confirmation
- When bodies are suppressed, read the boundary from **status, length, timing,
  and error shape** via `diffr.diff(victim_txn, attacker_txn)` — a 200 vs 403,
  or a "not found" vs "forbidden", still proves existence/ownership leakage.

## Chaining
- Pair with `hunt-open-redirect`/`hunt-ssrf-identification` when the id controls
  a fetched resource, and with `hunt-auth-bypass` when a token (not an object
  ref) is the lever.
