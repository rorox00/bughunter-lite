# LFI / traversal wrappers & encodings

Angles to escape normalization and to escalate read→include. All via
`transport.ScopedSession`; confirm with `diffr.diff`. Prove reach with a BENIGN,
non-sensitive target — never pull real credentials, keys, or user data.

## Traversal mechanics
- Depth: enough `../` to reach root, then descend to a known benign file.
- Encoding layers to defeat filters/normalizers: URL-encode and double-encode
  `/` and `.`; overlong/UTF-8 variants; mixed `..%2f`, `%2e%2e/`, `....//`
  (collapsing filters), backslashes on Windows stacks.
- Prefix/suffix handling: absolute path to ignore a base dir; if an extension is
  appended, use null byte `%00` (legacy), path truncation, or a wrapper that
  consumes the suffix.

## PHP stream wrappers (when PHP)
- `php://filter/...` — read source without executing; chain filters (e.g.
  base64-encode the resource) to retrieve a benign file's content intact.
  **php_filter_chain**-style oracles can even induce content — use only to
  confirm reach on a non-sensitive target.
- `php://input` — body-as-include when the param is `include`d and POST is used.
- `data://` and `data://text/plain;base64,...` — inline content as an include
  (read→exec escalation; prove with an inert marker only).
- `zip://` / `phar://` — read a file inside an uploaded archive; pair with
  `hunt-file-upload` to control the archive. `expect://` if present (direct
  command exec — treat as RCE reachability, do not run commands).

## Read vs include vs RFI
- **Read**: returns file bytes. Minimal proof = the out-of-dir content marker.
- **Include**: the file is *executed* — a benign local file with no code is
  still just read; escalation needs a controllable executable source.
- **RFI**: a remote URL loads (`http(s)://`, SMB/UNC) → full code exec. Prove
  the fetch happens with an `oast` callback (`hunt-ssrf-identification`
  overlaps); do not host or run a real payload.

## Target selection (keep it safe)
- Use a harmless, predictable file to prove the boundary crossing. Record where
  the boundary was crossed; that out-of-bounds read IS the finding.
