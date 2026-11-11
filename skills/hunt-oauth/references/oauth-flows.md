# OAuth / OIDC attack angles

Checklist for ATO-grade OAuth/OIDC bugs. Map the flow first (auth-code, implicit,
PKCE, hybrid; who is the IdP; who validates redirect_uri/state/token). All via
`transport.ScopedSession`; prove cross-account effect with `replay.cross_session`.
The engine scope gate still blocks off-scope hosts — demonstrate the *validation
flaw* (e.g. a bad variant is accepted), not an actual off-scope exfiltration.

## redirect_uri validation bypass
- Weak matching: prefix/suffix match instead of exact (`victim.com.attacker`,
  `attacker.com?x=victim.com`, `@`-authority confusion).
- Path/param laxity: extra path segments, `/../`, trailing slash, added query
  or fragment the validator ignores but the client honors.
- Subdomain/wildcard over-permissiveness; `localhost`/dev entries left enabled.
- **Open-redirect chain**: a registered redirect_uri that itself open-redirects
  (pair with `hunt-open-redirect`) forwards `code`/`token` onward.
- `response_mode`/fragment vs query tricks that relocate the token.

## state / CSRF binding
- Missing `state` → classic login-CSRF / forced account-linking.
- Present but not validated, static, predictable, or reusable across sessions.
- `state` not bound to the user's session (TOCTOU between start and callback).
- Confirm with two identities: attacker-initiated flow completes in the victim
  session, or vice-versa.

## PKCE (public clients)
- PKCE not required, or `code_verifier` not checked on exchange → intercepted
  `code` is redeemable. Downgrade `S256`→`plain`, or omit the challenge.

## Token / code handling
- `code` or `access_token` leaked via `Referer`, logs, browser history, or an
  injected image/CSS on the callback page.
- **Code reuse**: redeem the same authorization `code` twice.
- Token substitution across clients (client A's token accepted by client B).
- `id_token` validation gaps → `hunt-jwt` (alg=none, wrong `aud`/`iss`,
  unverified signature, missing `nonce`).

## OIDC / SSO account linking
- Link attacker's IdP identity to a victim's local account via an
  email/unverified-email collision, or link a victim's IdP to the attacker's
  account.
- "Login with X" where the email from the IdP is trusted without verification →
  pre-account-takeover (register victim's email, they later SSO in).
- Scope/consent escalation: broader scopes granted than the app should request.

Record the full request chain; the finding is the resulting access to **another**
user's account/session.
