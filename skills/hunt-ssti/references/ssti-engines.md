# SSTI engine fingerprints + escalation angles

After `{{7*7}}`/`${7*7}` evaluates, identify the engine, then prove code-eval
with the MINIMAL benign expression for that engine. Read-only discipline: show
capability (evaluate a constant, read a harmless config value); never spawn a
shell, exfiltrate files, or run destructive commands on a live target.

## Fingerprinting (discriminating probes)
- `{{7*7}}` → `49`: a `{{ }}` engine (Jinja2, Twig, Nunjucks, Handlebars-ish).
- `{{7*'7'}}` → `7777777` suggests **Jinja2/Python**; → `49` suggests **Twig/PHP**.
- `${7*7}` → `49`: **FreeMarker / JSP EL / Velocity-style** (`$`-delimited).
- `#{7*7}` → `49`: **Ruby/Slim/others** using `#{ }`.
- `<%= 7*7 %>` → `49`: **ERB / EJS / JSP** scriptlet style.
- `*{7*7}` / `~{}` : **Thymeleaf** expression dialects.
- Literal `7*7` echoed everywhere → not SSTI (KILL).

## Per-family escalation (categories, not a dump)
- **Jinja2 / Python** (`{{ }}`): reach the object/MRO graph from a benign
  builtin to the runtime; prove with a constant eval first, then note the
  gadget chain exists — don't execute OS commands.
- **Twig / PHP** (`{{ }}`): filter/function abuse (`filter`, registered
  functions); confirm a safe function call evaluates.
- **FreeMarker / Velocity** (`${ } / #set`): object/class access via exposed
  utility objects; prove with a harmless class/field read.
- **Handlebars / Nunjucks** (JS): prototype/require reachability; confirm with a
  benign JS expression evaluating server-side (distinguish from client CSTI).
- **ERB / Ruby**: expression eval context; prove with arithmetic/constant.

## Proof discipline
- Confirm evaluation (`49`, engine-specific discriminator), then ONE benign
  code-eval that only the server could compute (e.g. an internal constant).
- Stop at demonstrated capability: `proof_note:"RCE reachable, benign eval only;
  command execution NOT performed"`.
- Keep the exact request, the evaluated response, and the engine id as evidence.
