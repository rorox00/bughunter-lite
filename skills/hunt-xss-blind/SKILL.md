---
name: hunt-xss-blind
description: Blind XSS - a stored payload that executes later in a context you cannot see (admin/backoffice/log viewer). Use when input reaches an internal viewer (support tickets, user-agent/referer logs, feedback, order notes, contact forms). Confirmed only by an out-of-band callback. Triggers - blind xss, stored xss admin, backoffice xss, oob xss, log viewer xss. Siblings - hunt-xss-reflected, hunt-xss-stored, hunt-xss-dom.
---

# hunt-xss-blind
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Inputs that land in front of internal staff rather than you: support/helpdesk tickets, user-agent / referer / header logs and admin log viewers, feedback & contact forms, order/delivery notes, account/profile fields reviewed by staff, abuse reports. The sink is invisible from your session — OOB is the only oracle.

## Method
1. `oast = Oast(); oast.start()` — get a callback base (no-op if interactsh absent; without it this class cannot be confirmed).
2. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only, to submit the inputs.
3. For each candidate field, submit a payload that, when rendered, calls back: per-injection `cb = oast.new_url("bxss-<field>")` so a hit identifies the exact sink. Use callback-bearing variants (external script src, image/fetch beacon, and a few context break-outs) — the label, not the markup list, is the point.
4. Seed the quiet channels too (User-Agent / Referer headers, filenames) via `http`.
5. Wait for staff to view; `oast.poll(contains="bxss")` — a hit proves execution in another context. Re-poll over time; blind XSS is asynchronous.
6. `store` raw submissions + `sanitize.summarize_txn` in notes; map each callback label back to its injection point.

## Validate (triage-validation gate) — KILL if
- **No callback ever** — unconfirmed; it stays a lead, not a finding (markup appearing somewhere is not proof).
- The callback came from **your own view/session** (your browser rendered it, not an internal viewer) — check the OAST source/UA.
- The callback is a plain DNS ping from a scanner/preview bot with no script execution context.

## Done
An OOB callback (protocol + source) proving the payload **executed in another context**, tied to the exact field/header it was injected in. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "ticket body runs script in the support agent's authenticated backoffice session").
