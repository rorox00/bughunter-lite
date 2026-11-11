---
name: hunt-ssrf-postex
description: SSRF post-exploitation - after SSRF is confirmed (hunt-ssrf-identification), pivot through it to reach internal-only services, unauth admin panels, and cloud metadata. Use once you can make the server fetch attacker-chosen URLs. Triggers - ssrf exploit, internal pivot, ssrf to metadata, internal port scan, unauth admin via ssrf. Prereq - hunt-ssrf-identification.
---

# hunt-ssrf-postex
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
A confirmed SSRF primitive (per `hunt-ssrf-identification`): the server fetches a URL you control and you can observe the result (full-read) or infer it (blind/timing/OAST). Now turn reach into impact.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated; the SSRF param is the pivot, the internal targets are reached *by the server*, not by you directly.
2. **localhost first**: point the SSRF at `127.0.0.1`/`::1`/`169.254.x` and internal hostnames; scan common internal ports/services (see `references/ssrf-targets.md`). Use `diffr.diff` on status/length/timing to tell open vs closed when the body isn't reflected; use `oast` for blind confirmation.
3. **Unauth internal services / admin panels**: hit dashboards, config/metrics/health/debug endpoints, orchestration admin (e.g. Envoy `:9901`, actuator, internal consoles) that trust the internal network. Capture the response that proves access.
4. **Cloud metadata**: query the metadata service ONLY if it is actually reachable AND the SSRF lets you set any required header/version (modern IMDSv2 needs a token). Show the metadata response; do NOT exercise/replay any returned credentials — `proof_note:"creds reachable, NOT used"`.
5. Full-read SSRF: pull an internal response body back into the app response as proof. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- **No internal reach**: only public/external hosts are reachable (not a pivot — remains a plain SSRF at most).
- Internal ports all closed/filtered; metadata unreachable or header-locked and you can't set it.
- The "admin panel" is itself authenticated and you didn't bypass it.
- Reflected request without an actual internal response returned.

## Done
Access to an **unauth internal service / admin panel** OR exfiltrated internal config/metadata, shown read-only with the pivot request + the internal response. `confirmed`, `severity`, `proof_note` (what internal asset, creds-not-used), one impact line (e.g. "read cloud instance metadata / reach internal Envoy admin via SSRF").

## references/
`references/ssrf-targets.md` — common internal ports/services, metadata endpoints, localhost-first priority.
