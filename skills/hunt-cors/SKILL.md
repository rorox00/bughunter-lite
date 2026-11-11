---
name: hunt-cors
description: CORS misconfiguration - the server reflects an attacker Origin (or allows null/over-broad) together with credentials, letting a malicious site read a victim's authenticated data. Use when Access-Control-Allow-Origin reflects Origin, is null, or pairs Allow-Credentials:true with a loose origin. Triggers - cors, acao, access-control-allow-origin, cors credentials, origin reflection, cross-origin read.
---

# hunt-cors
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Responses on authenticated/sensitive endpoints carrying `Access-Control-Allow-Origin` that **reflects** the request `Origin`, is `null`, or is wildcard-ish — especially alongside `Access-Control-Allow-Credentials: true`. API/JSON endpoints that return user data.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Send the request with a series of `Origin` values and read the CORS response headers each time: an attacker origin (`https://evil.example`), a look-alike (`https://victim.com.evil.example`, `https://victimXcom`), a subdomain, `null`, and no Origin as baseline. Use `diffr.diff` on the returned `Access-Control-Allow-Origin`/`-Credentials` headers.
3. The win condition: the server returns `Access-Control-Allow-Origin: <attacker-controlled origin>` (or `null`) **and** `Access-Control-Allow-Credentials: true`, on a response that contains the victim's authenticated data. That lets `evil.example` fetch it with the victim's cookies.
4. Confirm it's **credentialed and sensitive**: the body behind it is per-user/secret (session token, PII, CSRF token). A reflected origin without credentials, or over non-sensitive public data, is not impactful.
5. `store` raw (all Origin variants + headers) + `sanitize.summarize_txn` in notes; record the exact Origin that got reflected.

## Validate (triage-validation gate) — KILL if
- `Access-Control-Allow-Origin` is a **fixed allowlist** / exact-match of legitimate origins (your attacker origin is **not** reflected).
- **No credentials** allowed (`Allow-Credentials` absent/false) — a cross-origin read with no cookies exposes nothing non-public.
- The data behind it **isn't sensitive** (public, unauthenticated content).
- Reflection appears but the browser wouldn't honor it (wildcard `*` with credentials is rejected by browsers → not exploitable as-is).

## Done
Attacker-controlled (or `null`) origin reflected in `Access-Control-Allow-Origin` **with** `Allow-Credentials: true` over sensitive, authenticated data — shown with the exact Origin sent and the response headers + a snippet proving the readable sensitive body. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "evil.example reads any logged-in user's profile/token via reflected CORS + credentials").
