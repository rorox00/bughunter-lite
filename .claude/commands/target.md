---
description: Switch the active target to a new authorized host.
argument-hint: <url>
---

Goal: switch the active target to the URL/host in **$ARGUMENTS**.

Steps:

1. Parse `$ARGUMENTS` into host + apex. If empty, ask for the target and stop.
2. **CONFIRM AUTHORIZATION for the NEW host** in one line ("Confirm you're authorized to test `<host>` — program, scope, or your own asset?") and **WAIT for yes** before anything else.
3. Auto-build `./engagements/<host>.json` = `{"name":"<host>","in_scope":["*.<apex>","<host>"],"out_of_scope":[],"seeds":["<url>"]}` (`mkdir -p engagements`). Make it the active engagement.
4. **Do NOT carry over the previous target's scope** — the new scope is exactly the new host/apex, so the deny-wins gate only ever permits this target.
5. Offer: **"/recon to map it, or /pentest to go end-to-end."**

Read-only until a hunt is explicitly started. In-scope only.
