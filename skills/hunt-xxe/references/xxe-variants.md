# XXE variants — blind and file-format angles

Use when a straight in-band entity returns nothing or the input is a document
upload. All traffic via `transport.ScopedSession`; `oast` is the oracle for
blind cases, `diffr.diff` for in-band. Benign proof only — read a harmless file
or land a callback; never pull secrets or fire entity-expansion DoS at prod.

## Blind / OOB (no reflected output)
- **External entity → callback**: reference an entity that resolves
  `http://<oast>/` (from `oast.new_url("xxe")`); a hit proves resolution.
- **Parameter entities**: when general entities are restricted, parameter
  entities (`% name`) inside the internal/external subset often still resolve —
  the standard blind-XXE route.
- **External DTD**: host a DTD at the OAST/your in-scope endpoint that defines a
  parameter entity which exfiltrates a benign value or just calls back; the
  target fetches the DTD (confirms both parse + SSRF).
- **Error-based**: force the file/value into a parser **error message** when the
  response otherwise hides it (entity referenced in a context that echoes on
  failure).

## SSRF via XXE
- Point the external entity at an internal URL instead of a file — proves
  server-side request reach even when file read is blocked. Chain with
  `hunt-ssrf-identification` for internal targets.

## File-format XXE (uploads)
- **SVG**: an SVG is XML — add a DOCTYPE + entity and reference it in a text
  node; triggers when the server rasterizes/parses the SVG (thumbnails,
  avatars, preview).
- **OOXML (DOCX/XLSX/PPTX)**: these are ZIP archives of XML parts. Inject the
  DOCTYPE/entity into a parsed part (e.g. document/sheet XML), re-zip, upload —
  fires when the server reads the document (text extraction, conversion).
- **Other XML carriers**: RSS/Atom import, sitemap upload, config/`.xml` import,
  SAML assertion, XMP metadata in images.

## Parser notes
- Identify the stack (Java/.NET/PHP/Python/libxml) — entity support, parameter
  entities, and external-DTD fetching differ per parser and version.
- If nothing resolves at all, external entities are likely disabled → KILL.
- Keep the exact payload, the resolved file snippet or OAST hit, and the
  endpoint as evidence.
