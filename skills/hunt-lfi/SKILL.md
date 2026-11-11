---
name: hunt-lfi
description: Path traversal / local file inclusion / arbitrary file read - a param controls a filesystem path the server reads or includes. Use when a param names a file/path/template/page to load (file, path, template, include, page, download, read, doc). Triggers - lfi, rfi, path traversal, arbitrary file read, directory traversal, file param, include.
---

# hunt-lfi
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Params that resolve to a filesystem path: `file`, `path`, `template`, `include`, `page`, `download`, `read`, `doc`, `view`, `lang`, `theme`. Tells: extensions auto-appended, slashes accepted, a filename echoed in a header (`Content-Disposition`).

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Baseline the legit value, then **traverse** toward a **benign, universally-present** file (a harmless OS/app file — not credentials or keys). Compare with `diffr.diff`: the appearance of file-shaped content that the baseline lacks is the signal.
3. Beat path normalization with the encodings/angles in `references/lfi-wrappers.md` (depth, encoding layers, prefix/suffix tricks, null/truncation).
4. **Distinguish read vs include**: plain read returns the bytes; if the target *executes* the included file (or a remote URL loads → RFI), that escalates to code exec — prove reachability read-only, no payload planting.
5. Try wrappers/filter chains (see reference) only to **confirm reach**, pulling a benign/non-sensitive resource — never exfiltrate real secrets.
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- Input is **sanitized/allowlisted** (traversal stripped, basename-only, fixed extension that holds) — your sequence didn't escape.
- `200` with **no file content** (same page, error, or just your input echoed) — not a read.
- The "file" is **intended downloadable content** served by design (a public asset, a user's own export).
- Only files inside the intended directory are reachable (no boundary crossed).

## Done
Read of a file **outside** the intended directory (or a confirmed include/RFI code path), shown with minimal, non-sensitive proof — the request + the out-of-bounds content marker. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "arbitrary file read of server config via ../ traversal in the page param").

## references/
`references/lfi-wrappers.md` — `php://`, `data://`, `zip://`, filter chains, null-byte/encoding, RFI, traversal encodings.
