---
description: Produce the findings write-up for the active engagement.
---

Goal: produce the findings write-up for the active engagement (most recent under `~/.bughunter-engagements/<name>/`).

Steps:

1. Read the engagement's **validated** findings from `state.json` and their `evidence/` files. Ensure `report.md` is current — regenerate it from the validated findings if it is stale or missing (the engine's report phase writes it; you may re-run `python3 engine/engine.py --scope <scope.json> --phases report` or rebuild it from state).
2. Present a concise summary — **per finding**: title, severity, affected endpoint, one-line impact, and the **reproducible request** from its evidence file.
3. Offer export options: keep as `report.md`, or build a **PDF** (use the `pdf` skill) / a Markdown copy.

Rules: include **VALIDATED findings only** (those that passed the 7-Question Gate in triage-validation). Never inflate severity — each severity must match the real business impact. If there are no validated findings yet, say so and point to `/status` for leads still in validation.
