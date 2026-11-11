---
name: hunt-source-leak
description: Source & secret exposure - reachable VCS dirs, env/config files, source maps, and backups that leak code or credentials. Use to verify the leads recon/js-analyze surface (.git/.env/.svn, .map, .bak/.old/~, config dumps). Covers the 'secret' and 'info-leak' classes. Triggers - source leak, exposed .git, .env exposure, source map leak, backup file, config dump, exposed secret. Found-by - recon, js-analyze.
---

# hunt-source-leak
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Artifacts that shouldn't be web-reachable (mostly surfaced by `recon` / `js-analyze`): `/.git/` (config/HEAD/index/packs), `/.svn/`, `/.hg/`, `.env`/`.env.*`, `*.bak`/`*.old`/`*~`/`*.orig`/`*.swp`, `config.php.save`, source maps (`*.js.map`), `*.sql`/DB dumps, `/actuator/env`/`/debug` config, `WEB-INF`, `composer.json`/`package.json` with internals.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only. Fetch each candidate artifact.
2. **Confirm it's a real leak**: the response actually contains source/secrets, not a 404/empty/placeholder. For `.git`, confirm it's browsable (readable `config`/`HEAD`, pack files) → source reconstructable. For `.map`, confirm original sources are embedded. Use `diffr`/content checks.
3. **Classify what's revealed** — secret TYPES only, values redacted (the engine already redacts via `recon`/`sanitize`): API keys, DB creds, private keys, internal hostnames/endpoints, tokens, source code.
4. **Scope a leaked secret PASSIVELY**: reason about what it would grant from its type/prefix/metadata; do NOT authenticate with it, call its API, or otherwise exercise it (`proof_note:"secret reachable, NOT exercised"`). If live-validity matters, note that the program should rotate and verify.
5. `store` the artifact reference + `sanitize.summarize_txn` in notes; never paste raw secret values into the report.

## Validate (triage-validation gate) — KILL if
- The path is **404/empty** or returns the app's SPA/placeholder, not the artifact.
- It's an **intended public file** (public `package.json`, a deliberately open repo, documented).
- The leaked secret is already **rotated, revoked, a sample/placeholder, or public** (e.g. a publishable client key).
- Source map present but reveals nothing non-public / no secret or sensitive logic.

## Done
The exposed file + what it reveals (secret **types** only, redacted; or source reconstructable from `.git`/`.map`), with the exact fetch request. `confirmed`, `severity`, `proof_note` (types, not-exercised), one impact line (e.g. "exposed .env leaks live DB + cloud credentials" — scoped, not used).
