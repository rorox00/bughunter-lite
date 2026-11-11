---
description: Hunt a specific vuln class on the active engagement.
argument-hint: <class>
---

Goal: hunt the vuln class named in **$ARGUMENTS** on the CURRENT engagement — the most recent one under `~/.bughunter-engagements/`. If none is active, ask which target to use (or point the user to /target or /pentest) and stop.

Steps:

1. Map the class name to its skill(s):
   - `idor` → hunt-idor · `rce` → hunt-rce · `sqli` → hunt-sqli · `nosqli` → hunt-nosqli
   - `ssrf` → hunt-ssrf-identification (+ hunt-ssrf-postex once confirmed)
   - `xss` → hunt-xss-reflected / -stored / -dom / -blind (pick by context)
   - `ssti` → hunt-ssti · `xxe` → hunt-xxe · `lfi` → hunt-lfi · `file-upload` → hunt-file-upload
   - `auth-bypass` → hunt-auth-bypass · `privesc` → hunt-privesc · `jwt` → hunt-jwt · `saml` → hunt-saml
   - `oauth` → hunt-oauth · `graphql` → hunt-graphql · `csrf` → hunt-csrf · `cors` → hunt-cors
   - `open-redirect` → hunt-open-redirect · `header-injection` → hunt-header-injection
   - `cache-poison` → hunt-cache-poison · `request-smuggling` → hunt-request-smuggling
   - `deserialization` → hunt-deserialization · `prototype-pollution` → hunt-prototype-pollution
   - `business-logic` → hunt-business-logic · `race-condition` → hunt-race-condition
   - `password-reset` → hunt-password-reset · `secret`/`info-leak` → hunt-source-leak
   If the class is unknown, list the available hunt classes and ask.
2. Load that hunt skill and work its methodology against the engagement's candidates of that class (from `arsenal.md`), using the engine helpers as the skill directs: `transport.ScopedSession` (scope-gate), and `replay`/`oast`/`diffr`/`toolbridge` where applicable. **Read-only.**
3. Validate each candidate through **triage-validation** (the 7-Question Gate); KILL false positives and move on.
4. Save evidence to the engagement's `evidence/` dir (non-zero bytes). Report each confirmed finding in one line with its severity, and update the running status.

Read-only, in-scope only (deny-wins). Only use `--allow-intrusive`/state-changing steps with a separate explicit authorization; never exercise leaked credentials.
