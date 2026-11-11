---
name: hunt-oauth
description: OAuth 2.0 / OIDC flaws leading to account takeover - redirect_uri abuse, missing/weak state, PKCE absence, token leakage, code reuse, and account-linking abuse. Use when you see /authorize, /callback, redirect_uri, state, code, or id_token. Triggers - oauth, oidc, sso, redirect_uri, oauth state, pkce, account takeover, code theft, account linking.
---

# hunt-oauth
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
OAuth/OIDC endpoints and params: `/authorize`, `/callback`, `redirect_uri`, `state`, `code`, `id_token`, `response_type`, `scope`, `client_id`, `nonce`, `prompt`. Social-login buttons and "link account" flows.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only. Map the flow (type, who validates what) first.
2. **redirect_uri validation**: try the bypass angles in `references/oauth-flows.md` (subdomain/path/suffix tricks, open-redirect chain, extra params) to see if a `code`/`token` can be delivered to an attacker-controlled-but-in-scope endpoint. The scope gate still blocks truly off-scope hosts — prove the *validation flaw*, not an off-scope exfil.
3. **state / CSRF**: is `state` present, unpredictable, and **bound** to the session? A missing/replayable/unchecked `state` → login-CSRF / account-linking. Test with two identities via `state.set_session` + `replay.cross_session`.
4. **PKCE**: for public clients, is PKCE required and `code_verifier` actually checked? Absence → code-interception ATO.
5. **Token leakage / code reuse**: `code`/`token` in referer or logs; can a `code` be exchanged twice; does `id_token` audience/issuer/signature get validated (→ `hunt-jwt`).
6. **Account linking**: can an attacker link their IdP identity to a victim's local account (or vice-versa)? Prove the cross-account effect with `replay`. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- A **strict redirect_uri allowlist** holds (exact match; your variants rejected).
- `state` is present, random, and **properly bound/validated** (replay rejected).
- No **attacker-controllable** step — every lever requires the victim's own secret/session you can't obtain.
- A "leak" that stays within the legitimate client and never reaches an attacker.

## Done
Demonstrated `code`/`token` theft, login-CSRF, or account-linking abuse that yields **another** user's account/session, with the full request chain. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "account takeover via redirect_uri path bypass stealing the auth code").

## references/
`references/oauth-flows.md` — redirect_uri bypass angles, state/PKCE checks, token leakage, OIDC/SSO account-linking.
