---
name: hunt-rce
description: OS command / code injection - attacker input reaches a shell, exec, or eval and runs on the server. Use when a param feeds a system command or interpreter (ping/dns/convert/export/ffmpeg/filename/host lookups, admin tools). Triggers - rce, command injection, os command, code injection, eval injection, shell injection.
---

# hunt-rce
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Params that plausibly reach a command/interpreter: `ping`/`host`/`dns` lookups, image/media `convert`/`ffmpeg`, `export`/`backup`, archive/PDF tooling, `filename`, git/URL fetchers, admin "run" utilities. Tells: errors mentioning a binary, delays on heavy input.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. **In-band**: append shell separators (`;` `|` `&&` `` ` `` `$()` newline) with a harmless command whose output is distinctive but benign (e.g. an `id`/`whoami`-equivalent or a fixed `echo`); `diffr.diff(baseline, variant)` for the injected output appearing. Context matters (quoted vs unquoted) — see `references/cmd-injection.md`.
3. **Blind**: no output → OOB. `oast.start()`, `cb = oast.new_url("rce")`, inject a `nslookup`/`curl`/`ping` to `<cb>`; confirm with `oast.poll(contains="rce")`. Also time-based (a conditional sleep → `elapsed_ms` delta beyond `diffr`'s `time_ms`).
4. **Code/EL injection** variants (eval, expression languages, deserialization) per the reference — confirm evaluation, not just reflection.
5. **Read-only proof only**: demonstrate execution with a benign command or a callback. NEVER plant a reverse shell, modify files, or run destructive commands on prod — `proof_note:"RCE confirmed via benign <id/echo/callback>; no shell planted"`.
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- Input is **quoted/escaped safely** (metacharacters neutralized; separators land inside a quoted arg with no breakout).
- Output is just your **echoed input**, not command output (no separator actually executed).
- There is **no command/code context** at all (param never reaches exec/eval).
- A time delta that is network noise, not a deterministic injected delay.

## Done
Confirmed execution: in-band command output (the benign marker) OR an OOB callback (protocol + source), with the exact request. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "OS command execution as the app user via the host param").

## references/
`references/cmd-injection.md` — separators/encoding, blind (time/OOB), code-injection & EL injection, deserialization-to-RCE pointer.
