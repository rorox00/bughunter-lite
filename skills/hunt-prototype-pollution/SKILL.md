---
name: hunt-prototype-pollution
description: Prototype pollution (client or server JS) - attacker keys like __proto__/constructor/prototype poison Object.prototype, changing app behavior. Use when input is merged/cloned/query-parsed into objects. Value needs a reachable gadget (XSS, DoS, auth/privesc, RCE), not pollution alone. Triggers - prototype pollution, __proto__, constructor prototype, object merge pollution, ppollution gadget.
---

# hunt-prototype-pollution
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Code paths that deep-merge/clone/extend attacker input or parse structured query strings into objects: JSON bodies merged into config/options, `?a[b]=c`/`?__proto__[x]=y` query parsing, recursive merge/`extend`/`defaultsDeep` utilities. Client JS from `js-analyze` using such helpers is a strong tell.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. Inject a pollution key into each sink: body `{"__proto__":{"bhl":"x"}}`, `{"constructor":{"prototype":{"bhl":"x"}}}`, or URL `?__proto__[bhl]=x` / `?constructor[prototype][bhl]=x`.
3. **Confirm the pollution took**: look for the injected property surfacing where it shouldn't — a reflected default, a changed response flag, a new field on unrelated objects. Compare with `diffr.diff(baseline, polluted)`. Server-side: probe a follow-up request that would read the polluted prototype.
4. **Trace to a gadget** (the actual finding): a polluted property that a sink later trusts →
   - client: a `__proto__`-controlled option flowing into an HTML/JS sink → DOM XSS (`hunt-xss-dom`);
   - server: a config/flag property that flips auth/privilege, enables SSTI/command options, or crashes the process (DoS — note, don't fire at prod).
5. Keep it benign: pollute a harmless marker property to prove control; demonstrate the gadget minimally. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- **No gadget / no impact**: the prototype is polluted but nothing in the app reads it to a security-relevant effect (pollution alone is usually info-only).
- The framework/runtime **blocks** `__proto__`/`constructor` (null-prototype objects, `Object.freeze`, input sanitizer) — injection doesn't take.
- The "new property" is just your reflected input on the object you sent, not a prototype-wide effect.
- Only self/cosmetic impact.

## Done
Confirmed prototype pollution **plus** a reachable gadget (XSS / auth-or-privilege flip / DoS vector / RCE path), shown with the injection request + the gadget's observable effect. `confirmed`, `severity`, `proof_note` (gadget + whether exercised), one impact line.
