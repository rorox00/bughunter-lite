# Request smuggling variants

Desync happens when the front-end and back-end disagree on where a request ends.
Craft these with byte precision (Burp via `mcp__burp__send_http1_request` /
`send_http2_request`) — the engine's HTTP client normalizes framing. Confirm with
the timing/differential method and keep every probe self-contained: desync only
your OWN follow-up, never capture other users' traffic on prod.

## Core HTTP/1.1 variants
- **CL.TE**: front-end uses `Content-Length`, back-end uses `Transfer-Encoding:
  chunked`. The back-end treats the trailing bytes (after the `0\r\n\r\n`) as the
  start of the next request.
- **TE.CL**: front-end uses `Transfer-Encoding`, back-end uses `Content-Length`.
  Opposite boundary disagreement.
- **TE.TE**: both support `Transfer-Encoding` but one can be made to ignore it by
  **obfuscating the header** so only one server honors it (e.g. odd casing,
  duplicate TE headers, space/tab tricks, bogus TE value, `TE: chunked\r\nTE: x`).

## Detection method (timing-first, safe)
1. Send a **control** request; record normal timing/response.
2. Send a desync probe whose chunking/length makes the back-end **wait** for
   more bytes (or mis-split) — a vulnerable chain shows a clear, repeatable
   delay or an anomalous response vs the control.
3. Repeat to rule out jitter. Timing-based detection avoids leaving a poisoned
   request queued for a real user.

## HTTP/2 downgrade variants
- When an HTTP/2 front-end rewrites to HTTP/1.1 for the back-end, the implicit
  H2 length can conflict with injected `Content-Length`/`Transfer-Encoding`:
  **H2.CL**, **H2.TE**, and H2 request-splitting via CRLF in header
  values/names. Use `send_http2_request` for these.
- H2 header-name/value CRLF injection to smuggle a second request.

## Proof discipline
- Confirm the **parser disagreement** with a benign marker landing on your own
  connection. Note that queue poisoning / cache poisoning / cred capture is
  *reachable* but DO NOT exercise it against prod
  (`proof_note:"desync confirmed; cross-user exploitation not attempted"`).
- Record: the exact probe bytes, the control, and the timing/response delta.
- Pairs with `hunt-cache-poisoning` (smuggle → poison) once desync is proven.
