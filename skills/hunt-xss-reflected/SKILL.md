---
name: hunt-xss-reflected
description: Reflected XSS - attacker input echoed into the immediate response and executed in the victim's browser. Use when input appears in the response (q/search/name/message/redirect/error, path segments, headers). Triggers - reflected xss, xss, html injection, script injection, reflected input. Siblings - hunt-xss-stored, hunt-xss-dom, hunt-xss-blind.
---

# hunt-xss-reflected
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Input reflected into the same response: `q`, `search`, `name`, `message`, `redirect`, `error`, plus path segments and request headers (`Referer`, `User-Agent`, `X-Forwarded-*`) that get echoed into pages.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Send a **unique benign marker** (e.g. `bhl9173x`) in each candidate sink; capture baseline vs marked with `diffr.diff` to find exactly where/how it reflects.
3. Determine the **reflection context**: HTML body, tag attribute (quoted/unquoted), inside `<script>`/JS string, URL/`href`, or comment — the context dictates the break-out.
4. Confirm the marker is reflected **unencoded** for that context (angle brackets/quotes/backticks survive as needed).
5. Build the **minimal executing** PoC for that context (DOM marker or `alert`-equivalent) and verify it actually runs, not merely appears. Try one header-based reflection if a param one fails.
6. `store` raw + `sanitize.summarize_txn` in notes; record the exact request + context.

## Validate (triage-validation gate) — KILL if
- Input is **HTML-encoded/escaped** (or quote-encoded) at the sink for its context — reflection without execution.
- Reflected only in a **non-executing** context (e.g. a header/value logged or shown as text, never parsed as markup).
- **Self-XSS**: requires the victim to paste into their own console/devtools, or only fires in the attacker's own session.
- Requires an unrealistic header/condition the victim's browser won't send.

## Done
A working, **non-destructive** PoC (DOM marker or benign `alert`) that executes in a normal victim's browser, plus the exact request and the reflection context. `confirmed`, `severity`, `proof_note`, one impact line (who gets scripted and what it exposes — session/CSRF/token theft potential).
