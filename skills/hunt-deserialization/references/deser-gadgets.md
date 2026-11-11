# Deserialization markers & gadget notes

Identify the format first, confirm it's actually deserialized, then prove
reachability with a benign property change or an OOB callback — never run a
command gadget on prod. All via `transport.ScopedSession`; `oast` is the blind
oracle, `diffr.diff` shows tamper effects.

## Format markers (decode base64 first if needed)
- **Java**: `rO0AB` (base64) / `\xac\xed\x00\x05` raw; `java.`/`javax.` class
  names visible after decode.
- **PHP**: `O:<len>:"Class":` (object), `a:` (array) — PHP `serialize()` output.
  Magic methods `__wakeup`/`__destruct` are the trigger.
- **.NET**: `ViewState` (often `__VIEWSTATE`), `AAEAAAD/////` (BinaryFormatter),
  `TypeConfuseDelegate`-style chains; `LosFormatter`/`ObjectStateFormatter`.
- **Python**: pickle opcodes after decode (`\x80\x04`, `(c`, `cos\nsystem`-like
  only in malicious ones); look for `__reduce__`.
- **Ruby**: Marshal `\x04\x08`; YAML `!ruby/object:` tags.
- **Node**: `node-serialize` `_$$ND_FUNC$$_`, `funcster`, or JSON with embedded
  function strings.

## Confirming deserialization (before gadgets)
- Change a benign property/length and resend: a parse error, a changed field,
  or a type error proves the blob is parsed as an object (vs opaque/validated).
- If it's signed (HMAC/encrypted ViewState with a MAC) and verified, you need
  the key — check `hunt-source-leak` for a leaked machineKey/secret; otherwise
  KILL.

## Gadget / escalation notes (authorized only)
- Public gadget tooling exists per ecosystem (ysoserial for Java, ysoserial.net
  for .NET, PHPGGC for PHP). Use ONLY to build a **callback-only** proof chain
  (DNS/HTTP to your OAST), not a command/shell payload, on an authorized target.
- Prefer a URLDNS-style / DNS-lookup gadget for first confirmation: it proves
  deserialization reaches a dangerous sink with zero host impact.
- Property-oriented programming (POP) chains in PHP/.NET can give file write/
  object injection short of RCE — still high impact; prove reachability only.

## OOB confirmation
- `cb = oast.new_url("deser")`, embed it in a DNS/HTTP gadget, submit via the
  blob, then `oast.poll(contains="deser")`. A hit = confirmed.
- Record: decoded format, the tamper/benign-gadget effect or the callback, and
  `proof_note` stating no command was executed and nothing was modified.
