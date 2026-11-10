---
name: triage-validation
description: Run on any candidate finding BEFORE writing a single line of report. The 7-Question Gate - every question must pass; one wrong answer kills the finding and you move to the next class, not the next excuse. Triggers - validate, triage, is this a real bug, should I report, gate check, submit or not.
---

# triage-validation

The 7-Question Gate. A finding earns a report only by passing all seven, in
order. The first "no" ends it: **kill the finding and move to the next class.**
One dead finding is not a dead engagement.

## The 7 questions (in order)

1. **Usable right now?** Write the step-by-step actions a real attacker takes,
   today, against the live target. If you cannot write concrete steps, it is not
   usable — stop.
2. **In-scope impact type?** The impact is on the program's **accepted** impact
   list (not an excluded category). If the program would not pay for this class,
   stop.
3. **Root cause on an in-scope prod asset?** The actual cause lives on a
   production asset that is in the allowlist — not staging, not a third party,
   not out-of-scope infra. If not, stop.
4. **Novel?** Not already known, not a duplicate of your own earlier report, not
   public/known-issue. If it is known/dup, stop.
5. **Demonstrated, not theoretical?** You observed the impact with captured
   evidence — not "this could allow." If you only reasoned it, stop and prove it
   (in-scope only).
6. **Severity matches real business impact?** Your severity reflects actual harm
   to a user or the business, not the scariest label the class could carry. If
   it is inflated, fix it or stop.
7. **Reproducible from the writeup alone?** A triager who has only your writeup
   (requests + evidence) can reproduce it without you. If not, it is not ready.

Pass all seven → write the report. Any "no" → drop it, pick the next candidate.

## Always rejected (do not report)

These are not findings on their own, regardless of how they are dressed up:

- Self-XSS (requires the victim to attack themselves)
- Missing/weak security headers alone
- SPF / DMARC / DKIM misconfiguration alone
- Clickjacking without a sensitive state-changing action
- Rate-limiting / brute-force absence alone
- Open redirect alone (no token/credential theft or chained impact)
- "SSRF" that is DNS-resolution only (no request reaches an internal target)

If one of these is **chained** into real impact, report the chain and its
impact — not the component.

## Severity sanity scale (CVSS-ish)

- **Critical** — RCE, full account takeover at scale, mass PII/fund exposure.
- **High** — auth bypass, IDOR exposing other users' sensitive data, stored XSS
  hitting other users, SSRF reaching internal services.
- **Medium** — reflected XSS needing interaction, CSRF on a meaningful action,
  limited IDOR, blind SSRF with confirmed callback.
- **Low** — minor info leak, self-limited issues with a real but small impact.
- **Info** — no demonstrated harm (usually not reportable).

If your chosen severity does not match the real blast radius, it is wrong —
lower it.

## 60-second pre-submit checklist

- [ ] All 7 gate questions answered **yes**.
- [ ] Not on the always-rejected list (or it is a chain with proven impact).
- [ ] Affected host confirmed in-scope; no PoC step touched an out-of-scope host.
- [ ] Exact request(s) captured and copy-pasteable.
- [ ] Response excerpt proving impact captured (secrets redacted).
- [ ] Severity matches real business impact.
- [ ] A stranger could reproduce it from the writeup alone.
