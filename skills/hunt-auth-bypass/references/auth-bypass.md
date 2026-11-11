# Auth-bypass angles (checklist)

Categories to work when a straight anon request is refused. Every probe runs
through `transport.ScopedSession` (read-only) and identity comparisons through
`state.set_session` + `replay.cross_session`/`authz_signal`. Prove real access;
never brute real accounts or burn live OTPs beyond what proves the flaw.

## Forced-browsing / 403 & redirect bypass
- Path tricks: trailing `/`, `/.`, `//`, `%2e`, case changes, `;`/matrix params,
  `.json`/`.;` extensions, path traversal to the guarded route.
- Header tricks: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`,
  `X-Forwarded-Host`, `X-Forwarded-Proto`, `Referer`, `X-Custom-IP-Authorization`.
- Method tricks: `GET`↔`POST`↔`HEAD`, `X-HTTP-Method-Override`, unexpected verbs.
- Follow where a `302 → login` would go: request the destination directly; check
  if the guard is only client-side (data already in the first response/JS).

## Session & cookie manipulation
- Swap another user's / a forged cookie or token (compare via `authz_signal`).
- Tamper flags: flip `role`/`admin`/`isAdmin` in a cookie or JWT claim (hand to
  `hunt-jwt` for alg/signature issues).
- **Session fixation**: set a known session id pre-login, authenticate, check if
  the same id is still valid post-auth (no rotation → fixation).
- Logout/rotation: does a session survive logout or password change?

## User / email enumeration
- Differential responses between existing vs non-existing accounts on login,
  signup, forgot-password, and resend flows — compare with `diffr.diff`
  (message text, status, length, timing). Report enumeration only as a chain
  enabler or when it leaks sensitive membership.

## OTP / MFA bypass angles (non-destructive)
- Response manipulation: does the client trust a `success:false`→`true` flip?
- Missing server-side binding: reuse of a verified step, skipping the 2nd factor
  by going straight to the post-MFA endpoint.
- Code reuse / no invalidation / no attempt-limit — prove the *logic* flaw with
  minimal attempts; do not mass-brute a real code.

## Rate-limit bypass (as a chain enabler)
- IP rotation via `X-Forwarded-For`, casing/param variation, endpoint variants,
  HTTP/2 multiplexing. Only matters when it unlocks another bypass (brute of
  OTP/login) — rate-limit absence alone is on the triage KILL list.
