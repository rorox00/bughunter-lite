# Upload bypass angles

Work the validation layers one at a time, then PROVE the consequence (served/
executed/traversed), not just acceptance. All via `transport.ScopedSession`;
keep every artifact benign — inert markers only, never a real web shell or an
overwrite of prod files.

## Extension checks
- Double extension (`x.php.jpg`, `x.jpg.php`), alternate exec extensions
  (`.phtml`, `.php5`, `.pht`, `.asp`, `.aspx`, `.jsp`, `.cer`, `.svg`, `.html`).
- Case variation, trailing chars: space, dot, `%00` null, `;`, `::$DATA`.
- Mismatched extension vs declared type (server trusts one, serves by another).

## MIME / Content-Type
- Spoof the multipart `Content-Type` (e.g. `image/png`) while the bytes are
  something else; test whether validation trusts the header over content.

## Magic bytes / content sniffing
- Prepend a valid image/file signature (GIF89a, PNG header) then the payload —
  passes a magic-byte check while the real handler runs the tail.
- **Polyglot**: a file valid as two types at once (e.g. image + HTML/JS, or
  image + archive) so the sniffer and the renderer disagree.

## Filename path traversal
- `../../` sequences (and encoded/double-encoded, backslash, overlong) in the
  filename to write outside the upload dir or overwrite a served asset.
- Absolute paths; UNC paths on Windows stacks.

## SVG / image XSS
- SVG is XML+script: embed a benign XSS marker; fires when the server renders
  the SVG inline for another viewer (avatar, preview) → confirm cross-session
  per `hunt-xss-stored`. (SVG can also carry XXE → `hunt-xxe`.)
- Image metadata (EXIF/XMP) reflected unencoded into a page.

## Archive extraction (zip-slip)
- An entry named `../../target` in a zip/tar that the server extracts without
  path normalization writes outside the intended dir. Prove with a benign file
  landing at a safe out-of-dir path.

## Upload-to-RCE (prove reachability, don't plant)
- Executable type stored in a web-served, script-enabled directory → request it
  to confirm it would execute. Demonstrate the PATH is reachable with an inert
  marker; `proof_note:"RCE path reachable, shell NOT planted"`.
- Config/`.htaccess`/handler-mapping upload that changes how other files run.

## Confirmation discipline
Fetch the stored file and show status/content-type/render behavior with
`diffr.diff`. The finding is the served/executed/traversed consequence —
acceptance alone is a lead (see KILL list).
