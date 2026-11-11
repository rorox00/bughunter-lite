---
name: hunt-saml
description: SAML signature & assertion flaws leading to authentication bypass / impersonation - signature exclusion, XML signature wrapping (XSW), unsigned-assertion acceptance, and NameID/attribute tampering. Use when you see SAMLResponse, SSO/ACS endpoints, or an IdP->SP login. Triggers - saml, saml response, xsw, signature wrapping, sso bypass, assertion tampering, nameid. Related - hunt-jwt, hunt-auth-bypass.
---

# hunt-saml
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
SAML SSO: a `SAMLResponse` (base64 XML, often deflated) POSTed to an ACS/`/saml/acs`/`/sso` endpoint, IdP-initiated or SP-initiated flows, `NameID`, `Assertion`, `Signature`, `Conditions`, `Audience`. You hold a valid assertion for YOUR account to tamper from.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only. Capture your own valid `SAMLResponse` and decode it (base64 + inflate) to see the XML structure, where the `Signature` sits, and what it covers.
2. **Signature exclusion**: strip the `<Signature>` element (or the whole signature) and submit — does the SP accept an **unsigned** assertion?
3. **XML Signature Wrapping (XSW)**: keep the original signed element but add a second, attacker-crafted `Assertion`/`Response` the SP processes while signature validation checks the original — vary placement (before/after, nested, matching/duplicated IDs). Classic XSW1–XSW8 placements.
4. **Assertion tampering**: change `NameID`/`Subject`/attributes (role, email) to a **victim** identity and re-submit; also test comment-truncation (`victim@x.com<!---->.evil`) and `Audience`/`Conditions`/validity bypass, wrong-issuer acceptance.
5. **Confirm impersonation**: the tampered/unsigned response logs you in as the **victim** — prove with `state.set_session` + `replay.cross_session`/`authz_signal` (you get the victim's session/data, not your own). Re-sign experiments mirror `hunt-jwt` logic for key issues.
6. `store` raw (original + tampered + response) + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The signature is **strictly validated** (exclusion/XSW/tamper → rejected; the SP verifies the signed element actually covers the consumed assertion).
- The assertion is **properly bound** (InResponseTo, Audience/Recipient, NotOnOrAfter, issuer all enforced).
- You only ever authenticate as **yourself** with your own valid assertion (expected SSO, not a bypass).
- The SP rejects unsigned assertions and unknown issuers.

## Done
A tampered or unsigned SAML assertion that the SP accepts and that grants **another** identity (victim login / elevated role), with the modified `SAMLResponse` + the resulting session. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "authentication bypass / arbitrary-user impersonation via XSW on the ACS endpoint").
