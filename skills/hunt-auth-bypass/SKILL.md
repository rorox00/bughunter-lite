---
name: hunt-auth-bypass
description: Authentication bypass - reach a protected resource without valid auth via forced browsing, session/cookie manipulation, or token swap. Use when you see admin/internal/debug routes, login flows, session cookies, or endpoints that 302 to login. Vertical privesc via token swap belongs here; object-ref swaps belong in hunt-idor. Triggers - auth bypass, forced browse, broken session, token swap, admin access, 403 bypass.
---

# hunt-auth-bypass
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Protected surface: `/admin`, `/internal`, `/debug`, `/actuator`, `/console`, management APIs. Login flows, session/JWT cookies, and endpoints that **302 to login** (the redirect itself marks a guarded resource).

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Forced browse protected paths as **anon** and as **low-priv**; confirm the resource genuinely requires auth first (a baseline authed `200` vs anon `302/403`).
3. Session/cookie manipulation: `state.set_session("admin", cookies=...)`, `("lowpriv", ...)`, then `replay.cross_session(http, url, {...})` + `replay.authz_signal`. A forged/other/tampered cookie or swapped token that grants access = broken session management / vertical privesc.
4. Try the 403/redirect-bypass angles (path/header/method tricks) and session fixation/enumeration checks in `references/auth-bypass.md`.
5. Prove the access is **real** (the protected data/action is actually returned), not a decoy. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The resource is **intentionally public** (documented, or every anon gets it — check `m["anon"]`).
- Anon **already** sees it (no boundary existed).
- `200` with an **empty/error/login body** — not real access to the protected content.
- You used a **valid credential** for that privilege level — that's expected use, not a bypass.

## Done
Access to a protected resource **without** valid auth for that level, with the exact request(s) that reproduce it. `confirmed`, `severity`, `proof_note`, and one impact line (e.g. "anon reads admin user list at /actuator/env").

## references/
`references/auth-bypass.md` — user/email enumeration, OTP/MFA bypass angles, rate-limit bypass, session fixation (checklist).
