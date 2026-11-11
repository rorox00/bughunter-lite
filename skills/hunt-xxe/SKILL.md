---
name: hunt-xxe
description: XML External Entity injection - a server XML parser resolves attacker-defined entities, enabling local file read, SSRF, or OOB exfiltration. Use when an endpoint parses XML (SOAP, SAML, SVG, DOCX/XLSX, RSS, XML APIs, Content-Type xml). Triggers - xxe, xml external entity, blind xxe, svg xxe, docx xxe, billion laughs. Related - hunt-ssrf-identification.
---

# hunt-xxe
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Anything that parses XML server-side: SOAP/XML APIs, SAML assertions, SVG uploads, OOXML files (DOCX/XLSX/PPTX are zipped XML), RSS/Atom, sitemap, config import, `Content-Type: application/xml|text/xml`. Also JSON endpoints that accept XML when the content-type is switched.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. **In-band**: define an external entity pointing at a **benign** local file (a universally harmless, non-sensitive path) and reference it in a reflected XML field; `diffr.diff(baseline, variant)` to see the file content surface in the response. Minimal proof only — do not exfiltrate secrets.
3. **Blind** (no reflection): `oast.start()`, `cb = oast.new_url("xxe")`, use an external entity (and parameter-entity/external-DTD form) that fetches `http://<cb>/`; confirm with `oast.poll(contains="xxe")`. See `references/xxe-variants.md`.
4. **File-format XXE**: inject the DOCTYPE/entity into an SVG or OOXML part and upload via `http`. (`references/xxe-variants.md`.)
5. Note SSRF reach (internal URL via entity) — chain with `hunt-ssrf-identification`. Do NOT send entity-expansion (billion-laughs) DoS at prod. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The XML is **not actually parsed** (body echoed/stored as text; entity never resolved).
- External entities are **disabled** — the entity returns empty/raw, no resolution (modern hardened parser).
- **DNS-only** callback with no file/data read and no internal reach — a lead, not confirmed impact.
- The "file content" is just your input reflected, not parser-resolved.

## Done
A benign local file read OR a confirmed OOB resolution (OAST hit with protocol + source), with the exact XML payload and endpoint. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "arbitrary file read / internal SSRF via SAML XML parser").

## references/
`references/xxe-variants.md` — blind (OOB + parameter entities / external DTD) and file-format XXE (SVG, DOCX/OOXML) angles.
