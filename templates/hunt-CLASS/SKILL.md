---
name: hunt-CLASS
description: TEMPLATE - not a live skill. Copy this directory to skills/hunt-<class>/ (e.g. skills/hunt-idor/), rename name to match the directory exactly (name == dir), and rewrite the description for that one vuln class (keep it under 1024 chars, lead with when to use it, end with trigger words). Lives under templates/ so it never auto-installs.
---

# hunt-CLASS (template)

A copy-me sample showing the required shape of a technique skill AND how a
hand-written skill wires into the deterministic engine helpers. Replace every
`CLASS` / `<class>` and all the prose below with the real class.

> Delete this blockquote on copy. To ship: `cp -r templates/hunt-CLASS
> skills/hunt-<class>`, set `name: hunt-<class>` (must equal the directory),
> rewrite the description, fill the sections. `scripts/lint_skills.py` enforces
> name == dir and description length.

## When to use

One or two lines: the signal that routes here (from `arsenal.md` /
`skill_map`), and the single question this class answers about real impact.

## How this wires into the engine (full commands, not tool names)

Every request goes through the in-code safety boundary — never raw sockets.

- **Scope gate** — all traffic via `transport.ScopedSession`, which refuses
  out-of-scope hosts and (by default) state-changing methods before anything
  leaves:
  ```python
  http = ScopedSession(scope, store=store, log=eng.log)
  txn = http.get("https://HOST/PATH?PARAM=FUZZ")   # 403/blocked if off-scope
  ```
- **Dual-session replay** (auth-bypass / idor classes) — register identities,
  then replay the same request and read the authz signal:
  ```python
  eng.set_session("owner",    headers={"Authorization": "Bearer A"})
  eng.set_session("attacker", headers={"Authorization": "Bearer B"})
  matrix = cross_session(http, "https://HOST/api/v1/invoices/42", eng.sessions())
  sig = authz_signal(matrix, "owner", "attacker")   # likely_broken_authz?
  ```
- **OAST** (blind ssrf / rce / xxe) — mint a per-test callback host, inject it,
  then poll (never a no-op crash if the binary is absent):
  ```python
  cb = oast.new_url("CLASS")                 # None if interactsh missing
  # ...send a request that references cb...
  hits = oast.poll(contains="CLASS")         # [] until an interaction lands
  ```
- **Differential analysis** — compare a baseline vs a variant and let the code
  decide what changed:
  ```python
  d = diff(baseline_txn, variant_txn)        # why[], interesting, json_keys_added
  ```
- **Tool bridge** — fan out with ffuf/nuclei; the scope guard runs before any
  process spawns and only anomalies come back:
  ```python
  hits = toolbridge.ffuf("https://HOST/FUZZ", "wordlist.txt", scope=scope)
  ```
- **Token-safe evidence** — raw bodies live on disk via `store`; feed the model
  only the compact summary:
  ```python
  tid = txn["id"]                            # store.record ran inside ScopedSession
  summary = summarize_txn(store.get(tid))    # shape + redacted headers, not the dump
  eng.evidence_file("hunt-NN-CLASS.md", render(summary))
  ```

## Checklist

- [ ] Routed here from `arsenal.md` (class matches).
- [ ] Target host confirmed in-scope before the first request.
- [ ] Baseline captured, then the variant/probe captured.
- [ ] Impact observed (not assumed) with a captured response excerpt.
- [ ] Siblings (neighbouring endpoints, same class) checked before reporting.
- [ ] Evidence written to a non-zero `evidence/hunt-NN-<class>.md`.
- [ ] Candidate handed to `triage-validation` (the 7-Question Gate).

## Define done

Done only when: every checklist box is ticked; each request left a `store`
record and a non-zero evidence file; the finding is reproducible from that file
alone; and `triage-validation` passed all seven questions. Otherwise it is a
lead, not a finding — leave it in the arsenal and move on.

## Kill-list (stop and drop immediately)

- Proving it would require touching an **out-of-scope** host → stop at the
  scope boundary; report only what you proved in-scope.
- Only self-impact, or only theoretical ("this could allow …") → drop.
- A state-changing action without explicit operator authorization → do not send.
- On the always-rejected list in `triage-validation` and not chained into real
  impact → drop.
- 5 minutes of only 401/403/404, or 20 minutes with nothing → rotate to the
  next candidate.
