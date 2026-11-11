---
description: Short progress view of the active engagement.
---

Goal: show a SHORT progress view of the active engagement (shorter than /status), most recent under `~/.bughunter-engagements/<name>/`.

Read `state.json` (and count `evidence/`) and output ONE compact block, no detail:

- **Phase**: the current phase
- **Hunted**: candidates hunted vs total as `X/Y` with a simple percent or a short bar
- **Classes**: done (comma list) vs pending (comma list)
- **Findings**: count by severity (e.g. "2 High, 1 Medium confirmed")

Keep it to that single block. Read-only. If no engagement exists, say so in one line.
