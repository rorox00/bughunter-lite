# Command / code injection angles

Confirm EXECUTION, not reflection. All via `transport.ScopedSession`;
`diffr.diff` for in-band output/timing, `oast` for OOB. Proof is a benign
command or a callback — never a reverse shell, file write, or destructive
command on a live target.

## Shell separators & context
- Separators: `;` `|` `||` `&` `&&`, command substitution `` `cmd` `` and
  `$(cmd)`, newline (`%0a`). Which works depends on the shell and how the input
  is embedded.
- Break out of quoting first: if the value sits in single/double quotes, close
  the quote before the separator; if it's an unquoted arg, inject directly.
- Argument injection: no separator needed — sneak an extra flag/option the
  binary honors (e.g. an output/eval flag) when you can't break the command.

## Encoding / filter evasion
- Encode metacharacters (URL/double-URL), use `${IFS}` for spaces, brace/quote
  insertion inside a word, concatenation, env-var indirection. Goal is reaching
  the shell parser, not a payload dump.

## Blind confirmation
- **OOB**: `nslookup`/`host`/`curl`/`ping` to `oast.new_url("rce")`; a hit is
  proof even with zero output. Best first choice for blind.
- **Time-based**: a conditional sleep/heavy op; require a clear, repeatable
  `elapsed_ms` delay over `diffr`'s threshold, confirmed with repeats.

## Code injection (not just OS)
- `eval`/`exec` of a server language: confirm with a benign arithmetic/constant
  eval that only the server could compute.
- **Expression-language injection** (SpEL, OGNL, MVEL, JEXL, Ruby ERB): often
  overlaps SSTI — see `hunt-ssti`. Prove evaluation with a safe expression.
- Template → code via `hunt-ssti` when the vector is a template engine.

## Deserialization → RCE (pointer)
- Signals: serialized blobs in cookies/params/bodies (Java `rO0`/`AC ED`, PHP
  `O:`, .NET/`ViewState`, Python pickle, Ruby Marshal, Node). These can reach
  RCE via gadget chains. Treat as high severity; confirm reachability with a
  benign callback/gadget where possible and STOP at proof — do not run a chain
  that executes commands on prod.

## Proof discipline
Minimal and benign: a fixed `echo` marker, an `id`/`whoami`-equivalent, or an
OAST callback. Record the exact request, the marker/callback, and the injection
context. `proof_note` must state that no shell was planted and nothing was
modified.
