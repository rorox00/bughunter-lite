---
description: Map a target deterministically (recon→rank→map) without hunting.
argument-hint: <url>
---

Goal: map the target in **$ARGUMENTS** WITHOUT hunting — free, deterministic, read-only.

Steps:

1. Parse `$ARGUMENTS` as the target URL/host. If empty, ask for it and stop.
2. **CONFIRM AUTHORIZATION** in one line ("Confirm you're authorized to test `<host>` — program, scope, or your own asset?") and **WAIT for yes** before any network action.
3. Auto-build scope (as in /pentest): derive host + apex, `mkdir -p engagements`, write `./engagements/<host>.json` = `{"name":"<host>","in_scope":["*.<apex>","<host>"],"out_of_scope":[],"seeds":["<url>"]}` so the deny-wins scope gate applies.
4. Run `python3 engine/engine.py --scope ./engagements/<host>.json` (default phases = recon,rank,map; **no agents**).
5. Present `arsenal.md` as a short table: **weight | class | where | skill**. Then give the recon highlights: live hosts, key endpoints, params, secrets-count, tech stack (from the engagement's state/output files).
6. End by offering: **"/hunt <class> to test any of these."**

Read-only, in-scope only. Do nothing that sends a state-changing request.
