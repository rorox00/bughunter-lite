---
name: hunt-xss-dom
description: DOM-based XSS and client-side template injection (CSTI) - attacker-controlled data flows into a client-side sink and executes without a server round-trip. Use when jsanalyze sinks.txt flags client sinks (innerHTML, document.write, eval, location=, .src=, dangerouslySetInnerHTML, postMessage, insertAdjacentHTML, setTimeout(string)). Triggers - dom xss, client-side xss, csti, source to sink, hashchange xss, postmessage xss. Siblings - hunt-xss-reflected, hunt-xss-stored, hunt-xss-blind.
---

# hunt-xss-dom
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Client-side sinks from `jsanalyze.sh` → `sinks.txt` (with `file:line`): `innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, `location=`/`location.href`, `.src=`, `dangerouslySetInnerHTML`, `insertAdjacentHTML`, `setTimeout`/`setInterval(string)`, `postMessage` handlers. Framework interpolation (`{{ }}`, `${ }`) hints CSTI.

## Method
1. Pull the sink list from `js-analyze` output; the page fetch/baseline uses `transport.ScopedSession(scope, store=store)` (read-only).
2. For each sink, **trace the source** backward: `location.hash`/`search`/`href`, `document.referrer`, `postMessage` data, `localStorage`/`sessionStorage`, URL-parsed params. See `references/dom-sinks.md` for the source→sink map.
3. Confirm a source **reaches** the sink unsanitized (follow the data flow in the deobfuscated JS; note the `file:line`).
4. Prove **execution in the browser** (the engine's HTTP layer cannot run JS): craft the source value (e.g. `#payload`) and verify a DOM marker / benign `alert` fires. For `postMessage`, send from an attacker origin; for CSTI, test `{{ }}`/`${ }` evaluation.
5. Record the source, the sink `file:line`, and the triggering URL/message. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The sink is fed only **server-controlled/constant** data (no attacker source reaches it).
- The framework **auto-escapes/sanitizes** that sink (e.g. textContent, trusted-types, Angular/React default binding) — interpolation shown as text.
- No source actually reaches the sink (dead code, guarded path, requires impossible state).
- Execution never occurs — only the string appears in the DOM inertly.

## Done
A source→sink PoC: the exact URL/`postMessage`/storage value that drives attacker data into the sink and executes in a normal victim's browser, with the sink `file:line`. `confirmed`, `severity`, `proof_note`, one impact line.

## references/
`references/dom-sinks.md` — source/sink map + CSTI (`{{ }}` / `${ }`) angles.
