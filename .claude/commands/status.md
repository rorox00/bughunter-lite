---
description: Report the current pentest status from the active engagement.
---

Goal: report the current pentest status. Read the active engagement — the most recent directory under `~/.bughunter-engagements/<name>/`:

- `state.json` (phase, candidates, findings, validated)
- `arsenal.md` (ranked surface)
- `report.md`
- count the files in `evidence/`

Then summarize concisely:

- **Target + current phase**
- **Surface**: N candidates mapped (top classes by weight)
- **Hunted**: which classes are done, which are still pending
- **Findings**: N confirmed — list each as class · severity · where; and N leads still being validated
- **Next**: the highest-value untested classes

If the user named something specific (e.g. "did you hunt open redirect?"), answer that directly — done / not yet / result — and offer to run it (`/hunt <class>`).

Read-only: this command only reads state, it sends no requests. If no engagement exists yet, say so and suggest `/recon` or `/pentest`.
