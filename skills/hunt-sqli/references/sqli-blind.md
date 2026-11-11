# Blind & non-obvious SQLi techniques

Angles for when there is no usable error and no reflected output. Categories and
the logic behind each — build the concrete payload for the detected DB. Every
request goes through `transport.ScopedSession`; `diffr.diff` is the oracle for
in-band blind cases and `oast` for out-of-band.

## Boolean-based (inference)
- Send a pair that differ only in a condition that is TRUE vs FALSE
  (`AND 1=1` vs `AND 1=2`, context-adapted). A real injection makes the two
  responses **deterministically different** (status/length/content) and benign
  input does not. Confirm both directions with `diffr.diff`.
- Extract one bit at a time (e.g. a character comparison) only as far as needed
  to prove control — not to exfiltrate data.

## Time-based (inference)
- A conditional sleep/heavy-compute that fires only when the condition holds.
  Compare `elapsed_ms` of true vs false; require a clear, repeatable delay above
  `diffr`'s `time_ms` threshold and rule out network jitter with repeats.
- Prefer this when boolean responses look identical.

## Out-of-band (OOB)
- When the DB can make external lookups, trigger a DNS/HTTP callback to
  `oast.new_url("sqli")` (platform-specific primitives for DNS resolution or
  file/UNC reads). Confirm with `oast.poll(contains="sqli")`. Best for fully
  blind, no-timing targets, and enables exfil channels — stop at confirmation.

## Second-order
- Inject in one request where it is stored (profile field, name, filename),
  then trigger execution in a **different** request/flow that later uses the
  stored value in a query. Track the two requests as one chain in evidence.

## Context & WAF notes
- Identify the injection context first (string, numeric, identifier/`ORDER BY`,
  `LIMIT`, `IN()`, JSON path) — the right break-out differs per context.
- WAF evasion is about reaching the parser, not a payload dump: casing,
  comments/whitespace, encoding layers, alternative operators. If the payload
  returns unchanged with no behavioral shift, it never reached the DB — not a
  finding (see the KILL list).

## Proof discipline
Minimal, controlled proof only: a version banner, or one boolean that flips on
command. Never enumerate or dump real user data — that is both out of scope for
"proof" and a privacy harm.
