---
name: js-analyze
description: Use after jsdiscover.sh + jsanalyze.sh run, to analyze extracted JS for a target: classify endpoints, group the API surface, flag likely-vulnerable functions and routes, list library CVEs, produce a markdown report + ready curl commands. Triggers - analyze js, js recon, endpoint analysis, api map, what did the JS reveal.
---

# js-analyze

The judgment layer over `jsanalyze.sh` output. The deterministic extraction has
already run — **read its files, do not re-extract or re-grep.** Your job is to
reason over what was found and produce an actionable report.

## INPUT CONTRACT (read, don't re-extract)

From the engagement directory:

- `endpoints.txt` — URLs/paths recovered from the JS
- `params.txt` — parameter names
- `apis.txt` — grouped API path fragments (incl. version markers)
- `secrets.txt` — secret detections (treat as types only; values are redacted)
- `sinks.txt` — dangerous-function matches as `file:line:code`
- `routes.txt` — admin/internal/debug route matches
- `flags.txt` — feature flags / toggles
- `comments.txt` — interesting code comments
- `libs.json` — retire.js output (libraries + known CVEs)
- `tech.txt` — detected frameworks/libraries

## JUDGMENT

- **Classify endpoints**: label each as live / historical / likely-unauthed /
  all; flag the statistically-vulnerable ones by gf class (redirect, ssrf,
  sqli, xss, lfi, idor, rce).
- **Group the API surface** by functionality (auth, billing, users, admin,
  files, …) and explicitly call out OLD versions still referenced
  (e.g. `/v1` alongside `/v2`).
- **Routes & flags**: surface admin/internal/debug routes, feature flags, and
  interesting comments (TODO/FIXME/secret/deprecated).
- **Sinks**: for each sink, name the plausible vuln class — DOM-XSS,
  open-redirect, postMessage, prototype-pollution, or SSRF — and keep its
  `file:line` reference.
- **Libraries**: from `libs.json`, list outdated libraries WITH their CVE ids.
- **Secrets**: report TYPES only; values stay redacted. Never exercise them.
- **Feature map**: one paragraph describing what the app appears to do, inferred
  from the surface above.

## OUTPUT

Write `js-report.md` to the engagement directory with these sections:

1. Feature map (one paragraph)
2. Endpoints (classified + gf flags)
3. API surface (grouped; old versions flagged)
4. Routes & feature flags
5. Interesting comments
6. Sinks → plausible class (`file:line`)
7. Library CVEs (from `libs.json`)
8. Secret types (redacted)
9. Ready curls

For every interesting endpoint, include ONE full curl in exactly this form:

```
curl -s -k -i -A 'bughunter-lite/0.2' -m 20 'https://HOST/PATH?PARAM=FUZZ'
```

Keep methodology and how-to-exploit guidance OUT of the report — it lists what
was found and the command to observe it, nothing more.
