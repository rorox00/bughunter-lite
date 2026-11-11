---
name: hunt-header-injection
description: CRLF / HTTP response splitting and Host-header injection - attacker input injects new response headers or an attacker Host used in links, resets, or cache keys. Use when input is reflected into a header, or the Host is trusted for links/redirects/reset emails/cache. Triggers - crlf injection, response splitting, header injection, host header injection, host poisoning, set-cookie injection. Related - hunt-password-reset, hunt-cache-poisoning.
---

# hunt-header-injection
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Input that reaches a response header or a trusted Host: a param echoed into `Location`/`Set-Cookie`/custom headers; `Location` built from input; the request `Host`/`X-Forwarded-Host` reused in links, password-reset emails, or as a cache key. Redirect endpoints and anything that reflects a value into response metadata.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only. Baseline the response headers.
2. **CRLF / response splitting**: inject encoded `\r\n` (`%0d%0a`, and `%0a`/`%0d` alone, double-encoded) followed by a new header (e.g. a benign `Set-Cookie: bhl=1` or a marker header) into the reflected param. Use `diffr.diff` on the response headers to see the injected header materialize as a real header (not body text).
3. **Host-header injection**: send an alternate/`evil.example` `Host` (and `X-Forwarded-Host`/`X-Forwarded-Server`) and check where it surfaces — absolute links, `Location`, or the password-reset email link (chain → `hunt-password-reset`), or as part of a cache key (chain → `hunt-cache-poisoning`).
4. **Confirm the consequence**, not just reflection: a genuinely injected header/cookie, a split response, or a Host that drives a link/reset/cache others receive. For cache/reset effects, show the poisoned artifact reaching a second request/victim.
5. Keep payloads benign (marker header/cookie); no malicious cache entries left in place. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- CR/LF is **stripped, encoded, or rejected** — the sequence never becomes a real header (shows as literal text in the body).
- The `Host` is **validated/allowlisted** (alternate Host ignored or 400'd) — no attacker Host propagates.
- The value is reflected only into the **body**, not a header, and there's no splitting.
- Reflection with no downstream impact (no cookie set, no link/reset/cache driven).

## Done
An actually-injected response header/cookie or split, OR a Host-driven impact (poisoned reset link / cache key / misrouted link), shown with the request + the resulting header/artifact. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "attacker Host poisons the password-reset link → ATO").
