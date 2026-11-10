---
name: review
description: Run at the END of a hunt, on a DIFFERENT model than did the work, to defeat completion bias. Verifies the checklist is fully ticked, every declared artifact exists and is non-zero bytes and actually ran per the log, and no PoC touches an out-of-scope host; then restarts failed steps or reports a critical failure. Triggers - review, verify run, is this done, completeness check, final check, did it actually finish.
---

# review

A completeness backstop. The worker that did the hunt is biased toward calling
it finished — this skill exists to disbelieve that and check. It does not
re-hunt; it verifies the run against its own claims.

**Run this on a DIFFERENT model than produced the work.** A fresh model has not
invested effort in the run and will not rationalize gaps as "good enough."

## What to check

1. **Checklist**: open the run's checklist. Any unticked item means NOT done.
   List every unticked item.
2. **Artifacts exist**: every artifact the run declared — `state.json`,
   `engine.log`, `arsenal.md`, `report.md`, each `evidence/hunt-NN-<class>.md` —
   is present on disk.
3. **Artifacts are real**: each artifact is **> 0 bytes** AND the tool that was
   supposed to produce it actually ran, confirmed by a matching line in
   `engine.log`. A file that exists but has no corresponding log entry is
   suspect — treat it as a failed step.
4. **Scope integrity**: no PoC, request, or evidence excerpt in any finding
   references an out-of-scope host. Grep every evidence file and `report.md` for
   hosts and confirm each against the allowlist. One off-scope host in a PoC is
   a critical failure.

## NUDGE to re-emit to the worker

When something is incomplete, re-emit this verbatim to the worker model and do
not accept a "done" until it comes back clean:

> Your run is not complete. The following items are unverified or failed:
> <list the exact unticked checklist items, missing/zero-byte artifacts, steps
> with no matching log line, and any out-of-scope host found>.
> Do not summarize or claim completion. Redo exactly those steps, produce the
> missing non-zero artifacts, and leave a log line for each tool call. Then stop
> and hand back for re-review.

## Outcomes

- **PASS** — every checklist item ticked; every declared artifact exists, is
  non-zero, and has a matching log line; no out-of-scope host anywhere. Only
  then is the run done.
- **CRITICAL FAILURE** — report immediately, do not restart, when: a PoC touches
  an out-of-scope host; the log shows a scope/read-only guard was bypassed; or a
  finding claims `confirmed: true` with no supporting evidence. These are not
  "redo the step" problems — surface them to the operator.

For everything else that is merely incomplete (unticked items, missing or
zero-byte artifacts, steps that never ran), send the NUDGE and re-review after
the worker redoes those steps.

## Why a different model

Completion bias is strongest in the model that did the work: it remembers
intending to do each step and reads that intent as completion. A different model
sees only the evidence on disk, so it catches the half-finished step, the
zero-byte log, and the finding asserted without proof.
