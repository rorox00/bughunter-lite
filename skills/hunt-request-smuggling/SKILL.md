---
name: hunt-request-smuggling
description: HTTP request smuggling / desync - a front-end and back-end disagree on request boundaries (CL vs TE, or HTTP/2 downgrade), letting an attacker prepend to the next request. Use when there is a front-end/back-end chain (CDN/proxy/LB) and ambiguous Content-Length/Transfer-Encoding handling. Triggers - request smuggling, http desync, cl.te, te.cl, te.te, h2 downgrade, http2 smuggling.
---

# hunt-request-smuggling
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
A multi-hop chain: CDN/reverse proxy/load balancer in front of an origin (`Via`, `Server`, `X-Cache`, differing error pages hint at two servers). Endpoints that accept `POST` with bodies; any sign the front and back parse `Content-Length`/`Transfer-Encoding` differently, or an HTTP/2 front-end that downgrades to HTTP/1.1 to the back.

## Method
1. `http = transport.ScopedSession(scope, store=store)` for baseline/recon. For byte-precise crafting, drive **Burp via the MCP tools** (`mcp__burp__send_http1_request` / `send_http2_request`) — raw framing and HTTP/2 need exact control the engine's client won't give.
2. Send paired CL/TE probes (CL.TE, TE.CL, TE.TE, and H2.CL/H2.TE downgrade variants — see `references/smuggling.md`). Use the **timing/differential** method: a probe that desyncs makes a follow-up request hang or return an anomalous response vs a control.
3. Confirm with a **benign, self-contained** marker: desync your OWN subsequent request (e.g. prefix routes to a harmless endpoint you control) so the proof lands on **your** connection, not another user's traffic.
4. NON-destructive discipline: never queue a payload that poisons, redirects, or captures **other users'** requests on prod. Prove the parser disagreement with a harmless delayed/split response; `proof_note:"desync confirmed with benign marker; no cross-user capture attempted"`.
5. `store` raw (probe + control + timing) + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- **No desync**: timing and responses are unaffected across CL.TE/TE.CL/TE.TE/H2 variants (the chain parses consistently).
- **Single server** / no front-end-back-end split — no boundary to disagree on.
- The "anomaly" is ordinary load/jitter, not a repeatable, probe-specific differential.
- Only your own connection is affected in a way that proves nothing (plain malformed request, not a cross-boundary desync).

## Done
A confirmed desync shown with a **harmless marker** (repeatable timing/response differential tied to a specific CL/TE/H2 probe, affecting only your own follow-up), with the exact probe + control. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "CL.TE desync on the CDN→origin chain; request queue poisoning reachable, not exercised").

## references/
`references/smuggling.md` — CL.TE / TE.CL / TE.TE and HTTP/2 downgrade (H2.CL/H2.TE/H2.TE-chunked) variants.
