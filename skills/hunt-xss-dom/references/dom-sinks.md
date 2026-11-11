# DOM XSS source→sink map + CSTI angles

Use with `jsanalyze.sh` → `sinks.txt` (`file:line`). DOM XSS needs BOTH an
attacker-controlled **source** and a dangerous **sink** with an unsanitized path
between them. Trace the flow in the deobfuscated JS; confirm execution in a real
browser (the engine's HTTP layer can't run JS).

## Sources (attacker-controllable client input)
- URL: `location.hash`, `location.search`, `location.href`, `location.pathname`,
  parsed query/fragment params.
- Cross-document: `window.name`, `document.referrer`, `postMessage` event `.data`
  / `.origin` (check the handler validates origin).
- Storage: `localStorage`, `sessionStorage`, cookies, IndexedDB.
- Reflected-into-JS server data that a client sink then re-parses.

## Sinks (execution or markup injection)
- **HTML**: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`,
  jQuery `.html()`, `dangerouslySetInnerHTML`.
- **Script eval**: `eval`, `new Function`, `setTimeout`/`setInterval` with a
  string arg, `execScript`.
- **Navigation / resource**: `location`/`location.href =`, `.src =` on
  script/iframe/img, `a.href` to `javascript:`, `open()`.
- **Attribute/event**: setting `on*` handlers, `setAttribute` of dangerous attrs.

## Flow confirmation
- Match a source to a sink with no sanitizer/encoder/trusted-types between them.
- Watch for partial sanitizers that miss the current context (e.g. strips `<>`
  but the sink is an attribute or `javascript:` URL).
- For `postMessage`: a handler that uses `event.data` without checking
  `event.origin` → send the payload from an attacker-controlled origin.

## Client-side template injection (CSTI)
- Frameworks that evaluate interpolation on the client: test whether `{{ 7*7 }}`
  / `${ 7*7 }` (framework-appropriate) **evaluates** (renders `49`) vs prints
  literally. Evaluation → sandbox-escape to JS execution is the real finding;
  literal render is inert (KILL).
- Common in legacy Angular expression contexts and ad-hoc template engines; map
  the exact delimiter and binding before crafting a PoC.

## Non-destructive proof
A DOM marker (unique element/attribute set by your payload) or a benign `alert`
is enough. Record the triggering URL/message + the sink `file:line`.
