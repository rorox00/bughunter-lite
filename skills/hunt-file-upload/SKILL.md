---
name: hunt-file-upload
description: Unrestricted / abusable file upload - bypass type checks to get a dangerous file stored, served, or executed (web shell, stored XSS via SVG, path traversal, zip-slip). Use on upload/import/attach/media/avatar endpoints. Triggers - file upload, unrestricted upload, upload bypass, web shell, svg xss upload, zip slip, path traversal filename.
---

# hunt-file-upload
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Upload/import/attach/media/avatar/document endpoints; profile pictures, ticket attachments, bulk import, logo/branding, resume/CV, CSV/XLSX import, archive upload. Note where the file is served back (URL, CDN path, inline render).

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Establish what the server **accepts and how it serves** a baseline benign file (stored path, content-type returned, inline vs attachment).
3. Probe the validation layers (see `references/upload-bypasses.md`): extension (double/alt/null/case), `Content-Type` MIME spoof, magic-byte/polyglot, filename **path traversal**, SVG/image that carries XSS, archive **zip-slip** on extraction.
4. **Confirm the consequence**, not just the upload: fetch the stored file and check it is served executable / rendered as markup (SVG XSS via a different viewer session) / written outside its dir (traversal) — use `diffr.diff` on the served response.
5. Keep it **benign & non-destructive**: a harmless marker file / inert SVG marker / traversal to a safe path — never plant a real web shell or overwrite prod files (`proof_note:"RCE path reachable, shell NOT planted"`).
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The file is **stored but never served/executed** (cold storage, forced download, random name, no exec) — no reachable impact.
- **Strict server-side validation holds** (re-encodes images, enforces magic bytes + extension + content-type together) and your bypass didn't actually pass.
- **Only you** can retrieve it (private to your session) and it never renders for/against anyone else.
- Accepted but sandboxed to a non-exec, correctly-typed path.

## Done
Proof the upload leads to XSS / path-traversal / RCE / stored-malicious serving, demonstrated minimally and non-destructively, with the upload request + the retrieval/execution request. `confirmed`, `severity`, `proof_note`, one impact line.

## references/
`references/upload-bypasses.md` — extension/MIME/magic-byte tricks, polyglots, path-traversal, zip-slip, upload-to-RCE.
