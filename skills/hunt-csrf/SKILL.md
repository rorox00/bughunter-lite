---
name: hunt-csrf
description: Cross-Site Request Forgery - a state-changing action a victim's browser can be made to perform cross-site, because anti-CSRF defenses are absent or bypassable. Use on state-changing POST/PUT/DELETE with no anti-CSRF token or a weak one. Triggers - csrf, xsrf, cross-site request forgery, samesite, csrf token bypass, state change no token.
---

# hunt-csrf
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
State-changing requests (`POST`/`PUT`/`DELETE`, or state-changing `GET`): change email/password, update settings, transfer, add member, delete. Tells: no anti-CSRF token, a token that isn't validated, cookie auth without `SameSite`, no re-auth on sensitive actions.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated. Capture the legit state-changing request as the authenticated user.
2. **Defense inventory**: is there an anti-CSRF token? Is the session cookie `SameSite=None`/absent (cross-site sendable) vs `Lax`/`Strict`? Does the action require re-auth or a custom header the form can't set cross-site?
3. **Token tests**: remove the token entirely; send an empty/garbage token; swap in **another user's** token (not validated per-session); reuse a fixed/static token; move the token between body/query/header. Confirm with `state.set_session` + `replay.cross_session` that the action still succeeds without the victim's valid token.
4. **Method / content-type tricks**: downgrade to `GET`, switch `Content-Type` to `text/plain`/`application/x-www-form-urlencoded`/multipart to dodge a JSON-only or preflight-triggering guard; `X-HTTP-Method-Override`.
5. Prove the **cross-site** shape works (a request a foreign origin could send: simple request, no custom headers, cookie-driven). Prove reachability read-only; do the actual state change only on **your own** account — `proof_note:"shown on own account"`. `store` raw + `sanitize.summarize_txn`.

## Validate (triage-validation gate) — KILL if
- `SameSite=Lax/Strict` on the session cookie **blocks** the cross-site send (and no token-less GET path exists).
- The anti-CSRF token is **present and properly validated** (removal/swap/reuse → rejected).
- The action **needs no auth** / is already public (nothing to forge).
- It only works with a custom header or non-simple request a cross-site page can't make (no clickjacking/other vector either).
- Self-only, non-sensitive state with no victim impact.

## Done
A working cross-site request that **changes state for the victim** (reproducible from a foreign origin, demonstrated on your own account), with the forged request + the resulting change. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "attacker changes a victim's account email cross-site → ATO").
