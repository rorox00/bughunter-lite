---
name: hunt-open-redirect
description: Open redirect - a param sends the user to an attacker-chosen external host. CHAIN-ONLY value; alone it is usually rejected by triage, so prove the chain (OAuth code/token theft, SSRF filter bypass, phishing with a trusted domain). Use on redirect/return/next/url/continue/dest/goto params and OAuth redirect_uri. Triggers - open redirect, open redirection, redirect bypass, redirect_uri, next param, url param redirect.
---

# hunt-open-redirect
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Redirect-driving params: `redirect`, `return`, `returnUrl`, `next`, `url`, `continue`, `dest`, `goto`, `callback`, `r`, plus OAuth `redirect_uri`. Tells: a `Location` header or client-side `location=` that echoes a param; a login flow that bounces back to a supplied URL.

## Method
1. `http = transport.ScopedSession(scope, store=store)` with redirects NOT auto-followed (the engine captures each 3xx hop and re-checks scope). Baseline the legit redirect.
2. Set the param to an **external** host and inspect the response: a `3xx` with `Location: https://evil.example/...` (or a client-side/meta/JS redirect) that leaves the app's domain = open redirect. The engine's scope gate will flag/stop the off-scope hop — that same block is your proof the redirect targets off-domain.
3. Beat weak validation (same tricks as redirect_uri): `//evil.example`, `https:evil.example`, `/\evil.example`, `@`-authority (`https://victim.com@evil.example`), whitelisted-substring (`victim.com.evil.example`), encoded/backslash/CRLF, and `javascript:`/`data:` for client-side sinks.
4. **Prove the chain** (this is where the value is): does it steal an OAuth `code`/`token` (→ `hunt-oauth`), bypass an SSRF allowlist (→ `hunt-ssrf-identification`), or carry a token/credential to the attacker host? Note the concrete downstream impact.
5. `store` raw + `sanitize.summarize_txn` in notes; record the exact param value and the off-domain `Location`.

## Validate (triage-validation gate) — KILL if
- The redirect stays **on-domain / allowlisted** (external host rejected or normalized away).
- **No sensitive chain**: a bare off-domain redirect with nothing attached — report alone is usually rejected (note it only as a chain enabler).
- Only `javascript:`/`data:` in a context that doesn't execute (then it's not even XSS).
- The "redirect" is a documented, intended outbound link.

## Done
An off-domain redirect you control **plus** the chain it enables (OAuth code/token theft, SSRF allowlist bypass, or credential/token leakage to the attacker host), with the request + the resulting `Location`/downstream effect. `confirmed`, `severity`, `proof_note` (the chain), one impact line.
