---
name: hunt-password-reset
description: Password-reset flaws leading to account takeover - host-header poisoning of the reset link, predictable/leaked/non-expiring reset tokens, tokens not invalidated, or resetting another account. Use on /forgot, /reset, reset-token flows and reset emails. Triggers - password reset, forgot password, reset token, host header poisoning, account takeover, reset link hijack. Feeds - ATO chains.
---

# hunt-password-reset
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
`/forgot-password`, `/reset`, reset-token params, "set new password" endpoints, and the reset **email** itself (link host, token format). Tells: the reset link host mirrors the request `Host`/`X-Forwarded-Host`; short/sequential/timestamped tokens; token echoed in responses or referer.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. **Host-header poisoning**: request a reset for an account **you control**, setting `Host` / `X-Forwarded-Host` / `X-Forwarded-Server` to an attacker host; check whether the emailed link (or any response) uses your host → victim clicking leaks their token to you. Prove with your own inbox.
3. **Token quality**: inspect your own reset token for predictability (sequential, timestamp-derived, short, weak random — see `hunt-idor`/id-formats reasoning) and leakage (in the response body, redirect, referer, or logs).
4. **Lifecycle**: is the token single-use and expiring? Reuse a consumed token; use an old token after a new request; check it's invalidated on login/password change.
5. **Binding**: does the reset bind token→account? Try completing a reset where the token is for account A but the submitted identifier is account B (parameter swap) — confirm cross-account with `state.set_session` + `replay.cross_session`.
6. Use **your own test accounts** for the destructive step; prove reachability without hijacking a real user — `proof_note:"intrusive, NOT performed on a real account"`. `store` raw + `sanitize.summarize_txn`.

## Validate (triage-validation gate) — KILL if
- Token is **strong, bound to the account, and single-use/expiring** (reuse/old/cross-account all rejected).
- The reset link host is **server-fixed** (Host header ignored) — no attacker-controllable link.
- No attacker-controllable step: every lever needs the victim's own token you cannot obtain or predict.
- Host reflected only in a non-email, non-link context with no impact.

## Done
A reset of **another** account (or theft of a victim's reset token via poisoned link), demonstrated on your own test accounts, with the request chain + effect. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "full account takeover via Host-header-poisoned reset link"). Feeds ATO chains.
