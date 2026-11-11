# JWT attack reference

Each attack targets a different verification mistake. The win is always: a token
the server **never issued** is accepted and grants another user's / elevated
access — prove it with `state.set_session` + `replay.cross_session`. Decode and
re-sign offline; only the final accepted token touches the target (via
`transport.ScopedSession`).

## alg:none (and variants)
- Set header `alg` to `none`/`None`/`NONE`/`nOnE`, drop the signature (keep or
  remove the trailing dot). If the library skips verification for "none", any
  claims are trusted. Tamper `sub`/`role` and test.

## Weak HMAC secret (HS256/384/512)
- If the token is HMAC-signed, the secret may be guessable/default/short. Crack
  it **offline** against the token (wordlist/brute). With the secret, re-sign
  arbitrary tampered claims. Report only if a re-signed token is accepted.

## Algorithm confusion (RS256 → HS256)
- The server verifies RS256 with a public key but the library also accepts
  HS256. Sign a tampered token with **HS256 using the RSA public key bytes** as
  the HMAC secret — the server "verifies" it with the same public key. Obtain
  the public key from JWKS/`jku`, a cert, or `x5c`.

## Header key-injection (kid / jku / x5u / jwk)
- **kid**: path traversal / command / SQL injection in the `kid` to make the
  server load a key you control or a predictable one (e.g. a file with known
  contents). Overlaps `hunt-lfi`/`hunt-sqli`.
- **jku / x5u**: point the key-set URL at an attacker-controlled (but in-scope
  per the scope gate) location hosting your key; if unrestricted, the server
  fetches and trusts it. (SSRF overlap — `hunt-ssrf-identification`.)
- **jwk** header: embed your own public key in the token header; vulnerable
  verifiers use it to "verify".

## Claim & validation gaps (layer on top)
- Tamper `sub`/`user_id`/`email` → impersonate (horizontal); `role`/`is_admin`/
  `scope`/`tenant` → vertical/cross-tenant.
- Missing checks: expired `exp` accepted, wrong/omitted `aud`/`iss` accepted,
  `nonce` not validated (OIDC → `hunt-oauth`), signature not checked at all.

## Proof discipline
Keep the exact forged token, the signing method used, and the response it
unlocked. A forged token rejected with 401/403 is a correctly-validating server
(KILL), not a finding.
