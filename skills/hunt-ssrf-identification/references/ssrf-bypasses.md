# SSRF bypass angles

Angles to try when a naive `http://<oast>/` injection is filtered or the target
is an allowlist/denylist. Categories, not payload dumps — pick the angle, then
construct the concrete value. Every attempt still goes through
`transport.ScopedSession` and stays in-scope; the OAST callback remains the
oracle for blind cases.

## 1. IP address encodings
The same internal address written so a weak parser or filter misreads it:
- Decimal / dword form of an IPv4 address.
- Octal- and hex-encoded octets (mixed radices).
- IPv4-mapped and compressed IPv6 forms; IPv6 brackets.
- Short/zero-elided and enclosed-IPv4 IPv6 notations.

## 2. DNS tricks
- **DNS rebinding**: a name that resolves to an allowed host on first lookup,
  then to an internal address on the fetch (TOCTOU between validation and use).
- Attacker-controlled name with a low TTL pointing at an internal target.
- Wildcard/nip.io-style names that encode an internal IP in the hostname.

## 3. Authority / userinfo confusion
- `@`-trick: `https://allowed-host@internal/` — filters read the left, the
  client connects to the right.
- Credentials + port juggling to hide the real authority.

## 4. Redirect chaining
- Point the param at an in-scope endpoint you control the redirect of (or an
  open redirect) that 302s to the internal target — the server follows it.
  Pair with `hunt-open-redirect`.

## 5. Alternative URL schemes
When only `http(s)` is expected, try schemes a permissive client supports:
`gopher://` (arbitrary TCP, e.g. to internal line protocols), `dict://`,
`file://` (local file read), `ftp://`. Note which the fetch library honors.

## 6. Parser confusion
- Fragment/query placement: `#`, `?`, and where the allowlist check splits vs
  where the client splits.
- Trailing dot on the host, extra slashes, backslashes, CR/LF/whitespace.
- Double / mixed URL-encoding of separators.
- Case and Unicode-normalization differences between the validator and client.

## Confirming impact (not just reach)
A bypass that only yields a DNS ping is still a lead. Escalate toward:
- Reaching cloud metadata or internal admin/health endpoints.
- Reading internal responses back into the app response (full-read SSRF).
- Port/service enumeration via timing (`diffr.diff` on elapsed_ms).
Keep each successful angle's exact request + OAST hit as evidence.
