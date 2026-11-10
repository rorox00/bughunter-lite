---
name: hunt-orchestrator
description: Use at the START of any authorized bug-bounty or pentest session, on a target switch, or whenever unsure what to do next. Confirms mode + scope, routes to the right technique skill, enforces session discipline, defines "done", and gates findings before they leave. Triggers - bug bounty, pentest, where do I start, what next, recon, hunt, validate, scope.
---

# hunt-orchestrator

The brain skill. Run this first and return to it whenever you are unsure. It
decides WHAT to do; the `hunt-*` skills decide HOW. Use full commands, never
tool names.

## STEP 0 — Engagement frame

Before anything else, confirm:

- **Mode**: authorized bug bounty, or authorized pentest? If neither is
  confirmed, stop.
- **Scope**: is the target host in the engagement allowlist? Confirm it against
  `scope.in_scope_host`. If not confirmed in-scope, **pick another target**.
- **Worst case**: state in one sentence the worst thing an attacker could do
  here. If you cannot, you do not understand the target yet — go learn it.

## STEP 1 — The only question that matters

> Can an attacker do THIS, right now, against a normal user, for real harm?

If no → move on. Do not chase theoretical issues, self-only impact, or
best-practice nits. Impact first.

## STEP 2 — Route to a technique

Run the deterministic map FIRST, then work highest impact-weight first:

```
python3 engine/engine.py --scope eng.json
```

That writes `arsenal.md` (ranked candidates). Route each class to its skill:

| class | skill |
|-------|-------|
| rce | hunt-rce |
| sqli | hunt-sqli |
| ssti | hunt-ssti |
| ssrf | hunt-ssrf |
| auth-bypass | hunt-auth-bypass |
| idor | hunt-idor |
| lfi | hunt-lfi |
| xxe | hunt-xxe |
| forgot-password | hunt-forgot-password |
| cache-poison | hunt-cache-poison |
| file-upload | hunt-file-upload |
| graphql | hunt-graphql |
| oauth | hunt-oauth |
| business-logic | hunt-business-logic |
| race-condition | hunt-race-condition |
| xss | hunt-xss |
| cors | hunt-cors |
| open-redirect | hunt-open-redirect |
| secret / info-leak | hunt-source-leak |

Take the highest-weight candidate first.

## STEP 3 — Session discipline

- **One class at a time.** Finish a class before starting another.
- **5-minute rule**: if a probe only yields 401/403/404 for five minutes, stop
  and change angle or target.
- **20-minute rotation**: if a class produces nothing in twenty minutes, rotate
  to the next candidate.
- **Hunt siblings**: when you find bug A, hunt its siblings B and C (same class,
  neighbouring endpoints) BEFORE reporting — one report, full blast radius.

## STEP 4 — Validate

Route every candidate finding through `triage-validation` before it counts.
One wrong answer kills the FINDING, not the engagement — drop it and keep going.

## STEP 5 — Define done

See `references/good-output.md` for the bar. A phase is done only when:

- Every step is a checked checkbox.
- Every tool call left a non-zero-byte log / evidence file.
- Each finding has a reproducible request and observed evidence.

## STEP 6 — Review handoff

Hand validated findings to the `review` skill for an independent pass before
they leave the engagement.

## Guardrails

- **Never touch an out-of-scope host — not even to prove a finding.** If proving
  it would require going off-scope, the proof stops at the scope boundary and
  you report what you have.
- **Read-only by default.** State-changing requests only with explicit operator
  authorization.
- Use full commands, not tool names, so every action is reproducible.
