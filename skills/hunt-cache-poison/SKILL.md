---
name: hunt-cache-poison
description: Web cache poisoning & cache deception - an unkeyed input (header/query/Host) alters a cached response served to other users, or path confusion makes a cache store private data. Use when responses are cached (CDN/reverse proxy) and inputs like X-Forwarded-*/Host aren't in the cache key. Triggers - cache poisoning, web cache deception, unkeyed input, x-forwarded-host poisoning, cache key, cdn poisoning. Related - hunt-header-injection, hunt-request-smuggling.
---

# hunt-cache-poison
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Cacheable responses (`Cache-Control`, `Age`, `X-Cache: hit/miss`, CDN headers) that reflect an input not in the cache key: `X-Forwarded-Host`/`-Scheme`/`-For`, `Host`, extra query params, odd headers. For deception: static-looking paths that actually serve dynamic/authenticated content.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. **Find an unkeyed input that reflects**: send a candidate (e.g. `X-Forwarded-Host: evil.example`, a junk query param) and check it is reflected into the response (a link, script src, redirect, header). `diffr.diff(baseline, injected)`.
3. **Prove it's keyed-out and cached**: the reflection persists on a **clean** follow-up request that omits the input (and from a different session), and cache headers show a hit — meaning your injected value is now served to **everyone** hitting that key. Use a benign unique marker and a cache-buster-free request to confirm.
4. **Cache deception**: append a static-looking suffix/segment (`/account.css`, `;.js`, `/foo/..%2f`) to a private page; if the cache stores the authenticated response under a cacheable path, another user (or you unauth) can retrieve it. Confirm the private data is served from cache.
5. Keep it benign and **clean up**: use a harmless marker; prefer a unique path/param so the poisoned entry is isolated, and let it expire / request a purge — never leave a harmful entry poisoning real traffic (`proof_note:"benign marker, isolated key"`).
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The input is **keyed** (it varies the cache key, so only your own request gets it) — no cross-user effect.
- The response is **not actually cached** (no hit on follow-up; `Cache-Control: no-store`/`private`).
- Reflection exists but is **not harmful** (no script/redirect/sensitive content; cosmetic only).
- Deception path isn't actually cached, or serves only public content.

## Done
A poisoned cache entry (harmful reflection served to other users from cache) OR cached private data via deception, demonstrated minimally with a benign/isolated marker, with the injecting request + the clean cache-hit proof. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "X-Forwarded-Host unkeyed → cached redirect/script poisons all users of the page").

## references/
`references/cache.md` — unkeyed-input candidates, cache-deception path tricks, safe confirmation/cleanup.
