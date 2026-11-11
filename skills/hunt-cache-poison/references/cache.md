# Cache poisoning / deception reference

Two bug classes: **poisoning** (an unkeyed input changes a cached response served
to others) and **deception** (path/extension tricks make a cache store private
content). All via `transport.ScopedSession`; `diffr.diff` compares injected vs
clean. Benign markers and isolated keys only — never leave a harmful entry in a
shared cache; let it expire or request a purge.

## Reading the cache
- Indicators: `Cache-Control`, `Age`, `Expires`, `X-Cache`/`CF-Cache-Status`/
  `X-Cache-Hits` (hit vs miss), `Vary` (what IS keyed), CDN `Server`/`Via`.
- A cache-buster (unique junk query) forces a MISS so you can seed, then a
  clean request confirms the poisoned value is served without your input.

## Unkeyed-input candidates (poisoning)
- Host family: `X-Forwarded-Host`, `X-Forwarded-Scheme`/`-Proto`,
  `X-Forwarded-Port`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`.
- `X-Forwarded-For` / `True-Client-IP` reflected into content.
- Extra query params or `;`-params not in the key; duplicate params.
- Unusual headers the app reflects (debug, locale, feature toggles).
- Fat GET (body on a cached GET) where the back-end reads it but the key ignores
  it. Chain from `hunt-header-injection` when the input lands in a header.

## Harmful reflection sinks (makes poisoning matter)
- Reflected into a `<script src>`/`<link href>`/import → attacker JS for all.
- Reflected into a redirect/`Location` → traffic hijack (chain
  `hunt-open-redirect`).
- Reflected into HTML → stored-like XSS served from cache.
- A cached error/empty page → cache-poisoning DoS (note, keep isolated).

## Cache deception (store private content)
- Append a static-looking suffix to a dynamic/authenticated path so the cache
  caches the response: `/account.css`, `/account.js`, `/account/avatar.png`,
  trailing `;foo.css`, path-normalization gaps (`/account%2f..%2fcss`,
  `//`, `/./`). Different front/back path parsing is the lever.
- Confirm a SECOND party (you unauth, or another session) retrieves the private
  body from cache — that cross-user retrieval is the finding.

## Smuggling-driven poisoning
- When a desync exists (`hunt-request-smuggling`), a smuggled request can poison
  the cache for other users — but keep PoCs isolated and do not poison real
  traffic on prod.

## Proof & cleanup
Record the injecting request, the clean cache-HIT showing the poisoned/leaked
response, and cache headers. Use a unique path/param to isolate the entry; state
reversibility in `proof_note`.
