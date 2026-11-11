---
description: List only the confirmed/validated findings for the active engagement.
---

Goal: list ONLY the confirmed/validated bugs for the active engagement (most recent under `~/.bughunter-engagements/<name>/`).

Read `state.json` and present the validated findings as a compact table:

| # | class | severity | endpoint / param | one-line impact |

Sort by severity, **Critical → High → Medium → Low** (then Info). Keep it to one row per finding, no prose.

If nothing is confirmed yet, say so plainly and show how many leads are still being validated (from `state.json`).

Read-only: this command only reads state; it sends no requests. If no engagement exists, say so and suggest `/recon` or `/pentest`.
