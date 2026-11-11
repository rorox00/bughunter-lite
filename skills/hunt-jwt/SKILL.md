---
name: hunt-jwt
description: JWT validation flaws leading to privesc / account takeover - forge a token the server accepts (alg:none, weak HMAC secret, RS256->HS256 confusion, kid/jku/x5u injection, claim tampering). Use when you see Authorization: Bearer eyJ... or a JWT cookie. Triggers - jwt, json web token, alg none, hs256 rs256 confusion, jwt secret crack, kid injection, token forgery.
---

# hunt-jwt
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
`Authorization: Bearer eyJ...`, JWT in cookies/body/localStorage. Three base64url segments (`header.payload.signature`). Decode header (`alg`, `kid`, `jku`, `x5u`) and payload (`sub`, `user_id`, `role`, `tenant`, `exp`, `aud`, `iss`).

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only. Decode the token (no verify) to see claims and header.
2. Forge a token with the attacks in `references/jwt-attacks.md`:
   - **alg:none** (strip signature) — server skips verification.
   - **weak HMAC secret** — crack it offline, re-sign tampered claims.
   - **RS256→HS256 confusion** — sign with the public key as the HMAC secret.
   - **kid/jku/x5u injection** — point verification at a key you control / SQLi/LFI via `kid`.
   - Claim tamper on top: `sub`/`user_id` → victim, `role`/`is_admin` → elevated.
3. **Prove it grants access**: `state.set_session("forged", headers={"Authorization":"Bearer <forged>"})`, then `replay.cross_session(http, url, {...})` + `replay.authz_signal` — the forged token must return **another user's / admin** data.
4. The forged token must be one the server **never issued** — a legitimately-held token proves nothing. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The signature is **properly verified**: any tamper/forge → `401/403` (your forged token is rejected).
- The token you used is a **valid one you legitimately hold** (that's expected auth, not forgery).
- `alg:none`/confusion returns 401 (server enforces the expected alg + key).
- A cracked "secret" that doesn't actually produce an accepted token.

## Done
A token **YOU forged** (never issued to you) that the server accepts and that grants another user's or an elevated session, with the forged token + the response it unlocked. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "admin takeover via RS256→HS256 confusion forging role=admin").

## references/
`references/jwt-attacks.md` — alg:none, weak-secret crack, alg confusion, kid/jku/x5u injection.
