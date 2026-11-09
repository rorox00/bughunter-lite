---
name: content-discovery-wordlist
description: Use to build a target-specific content-discovery wordlist from the tech stack and JS analysis — paths generic lists (raft, onelistforall) miss. Triggers - make a wordlist, content discovery, custom fuzz list, build paths for ffuf, discovery list.
---

# content-discovery-wordlist

Build a **tight, target-specific** content-discovery wordlist by inferring paths
from what the engagement already learned about the target — the paths that
generic lists (raft, onelistforall, SecLists) do not contain because they are
specific to this stack and this app.

## INPUT

Read from the engagement directory:

- `tech.txt` — detected frameworks / libraries.
- `js-report.md` and/or `endpoints.txt` — endpoints, routes, params, comments
  and feature flags recovered from JS analysis.

## JUDGMENT (inference, not extraction)

This skill reasons about the inputs; it does not merely copy lines out of them.

### 1. Framework paths (from `tech.txt`)

Add the well-known sensitive paths for each detected framework:

- **Laravel** → `/telescope`, `/horizon`, `/_ignition`
- **Spring** → `/actuator`, `/actuator/env`, `/actuator/heapdump`
- **Next** → `/_next/static`, `/_next/data`
- **Django** → `/admin`, `/static`, `/__debug__`
- **Rails** → `/rails/info/routes`

### 2. Siblings (from observed endpoints)

For each endpoint seen, generate plausible neighbours:

- **Version bumps**: `/v1` → `/v2`, `/v3`, `/internal`
- **CRUD siblings**: `list` → `create` → `update` → `delete`
- **Plurals / singulars**: `/user` ↔ `/users`
- **Backup / temp variants**: append `.bak`, `.old`, `~`, `.swp`, `.orig`

### 3. Referenced-but-unlinked paths

From comments and feature flags, add any path that is named in the code but is
not reachable from the live crawl (dormant admin tools, debug routes,
flagged-off features).

### 4. Merge + tighten

Merge a **small** generic base (a handful of high-value paths only), then
**dedup**. Keep the list TIGHT — quality over size. A focused list of a few
hundred inferred paths beats a 60k generic dump.

## OUTPUT

Write `wordlist.txt` to the engagement directory. Then **state** the exact fire
command below — do NOT run it:

```
ffuf -u https://HOST/FUZZ -w wordlist.txt -mc 200,201,204,301,302,307,401,403,405,500 -ac -t 50 -rate 50 -o ffuf.json -of json
```

> Firing is done by the engine's `toolbridge.ffuf`, which runs ffuf in scope and
> returns anomalies only. This skill never sends requests itself.
