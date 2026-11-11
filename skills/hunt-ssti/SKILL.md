---
name: hunt-ssti
description: Server-side template injection - attacker input is evaluated by a server template engine, often escalating to RCE. Use when input is rendered through a template (email/name/profile/subject reflected with math-eval behavior). Client-side interpolation is hunt-xss-dom. Triggers - ssti, template injection, jinja2, twig, freemarker, velocity, handlebars, server template rce.
---

# hunt-ssti
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
User input rendered by a server-side template: display names, email/subject bodies, invoice/PDF fields, profile fields, error templates, any value reflected into a page that could be interpolated. Tell: arithmetic in curly/hash/dollar delimiters comes back **computed**.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Send a **polyglot math probe** that covers common delimiters at once, e.g. `${7*7}` `{{7*7}}` `#{7*7}` `<%=7*7%>` `*{7*7}`; capture baseline vs probe with `diffr.diff`.
3. **Evaluation, not reflection**: a response containing `49` (not the literal `7*7`) proves server-side evaluation. Vary operands (`7*7` vs `6*6`) so it can't be a coincidental string.
4. **Fingerprint** the engine with the discriminating probes in `references/ssti-engines.md` (e.g. `{{7*'7'}}` → `49` Twig vs `7777777` Jinja2).
5. **Escalate carefully, read-only**: demonstrate code-eval capability with a **benign** proof for that engine (e.g. evaluate a constant/config expression). Do NOT spawn a shell, read sensitive files, or run destructive commands — `proof_note:"RCE reachable, benign eval only"`.
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The math is **reflected as text** (`7*7` echoed, not `49`) — no evaluation.
- Evaluation is **client-side** (framework interpolation in the browser) — that's `hunt-xss-dom`/CSTI, not SSTI.
- Only a sandboxed/safe expression context with no path to code (note as low, not RCE).

## Done
Confirmed server-side template **evaluation** + identified engine, plus a minimal, benign code-eval proof. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "RCE on the app server via Jinja2 SSTI in the display-name field").

## references/
`references/ssti-engines.md` — per-engine fingerprint/payloads (jinja2/twig, freemarker/velocity, handlebars/nunjucks) + ssti-to-rce angles.
