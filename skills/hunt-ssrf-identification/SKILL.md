---
name: hunt-ssrf-identification
description: Detect Server-Side Request Forgery - confirm the server (not your browser) makes an attacker-controlled request. Use when a param takes a URL/host/path the server fetches, or on PDF/screenshot/preview/import-from-url/SVG/XML features. Triggers - ssrf, blind ssrf, server-side request, url param, webhook, callback, fetch, import url.
---

# hunt-ssrf-identification
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Params the server dereferences: `url,uri,target,dest,redirect,callback,webhook,img,image,load,fetch,proxy,site,host,feed`. Highest signal: PDF/screenshot/preview generators, import-from-URL, webhooks, SVG/XML/XXE-adjacent parsers, link unfurlers — features that fetch by design.

## Method
1. `oast = Oast(); oast.start()` — get a callback base (no-op if interactsh absent).
2. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
3. For each signal param: `cb = oast.new_url("ssrf")`, send the request with the param set to `http://<cb>/` via `http.get(url_with_cb)` (and header/body variants).
4. `oast.poll(contains="ssrf")` — a DNS/HTTP hit proves a **server-side** callback. (curl can't observe blind OOB; the callback is the oracle.)
5. No callback? Use `diffr.diff(baseline, variant)` on response time/status to separate open vs closed internal ports (connect-timeout vs instant refuse).
6. Blocked/filtered? See `references/ssrf-bypasses.md` for bypass angles.
7. Record raw via `store`; keep notes with `sanitize.summarize_txn(txn)`.

## Validate (triage-validation gate) — KILL if
- DNS-only callback with **no** data returned and **no** internal reach — not yet a bug (note as lead).
- The callback resolves from **your browser/client**, not the server (check the egress IP/UA — if it's you, it's not SSRF).
- The fetch is an **intended, documented** integration to an allowed destination.
- Reflection of your URL in the body with no actual request made.

## Done
Confirmed server-side callback (protocol + egress IP in the OAST hit) OR demonstrated internal/metadata/data reach. Record request(s) + proof, `confirmed`, `severity`, `proof_note`, and one business-impact line (e.g. "reaches cloud metadata / internal admin from prod").

## references/
`references/ssrf-bypasses.md` — bypass angles when naive injection is filtered.
