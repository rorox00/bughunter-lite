---
name: hunt-business-logic
description: Business-logic / broken-flow abuse - bend a money/count/state flow to gain value the design never intended. Use when a flow moves money, counts, quota, or state (checkout, refund, coupon, transfer, subscription, invite, booking). Triggers - business logic, logic flaw, price tamper, coupon abuse, step skip, race on state, negative quantity.
---

# hunt-business-logic
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Flows with value or state: checkout/payment, refund/credit, coupon/promo, balance transfer, quota/limits, subscription/tier, invite/referral, booking/reservation. Multi-step wizards and anything with client-side validation.

## Method
1. **Model the intended flow** end to end (the states, the invariants, who pays/gains what). Capture a clean baseline per step via `transport.ScopedSession(scope, store=store)`.
2. Break **ONE assumption per request** and `diffr.diff(baseline, variant)` the outcome:
   - price/amount/currency tamper; negative/zero/huge/decimal quantity.
   - step-skip (jump straight to `/success`/confirm without pay); reorder steps.
   - coupon replay / stacking; reuse a one-time token.
   - inject a privileged field (`role`, `tier`, `price`, `discount`) in a later request the client never sends.
   - client-validation bypass (send what the JS would block).
3. Timing/concurrency belongs to `hunt-race-condition`; reference it when a check-then-act window appears.
4. Prove reachability read-only; do not complete a real purchase/refund — `proof_note:"intrusive, NOT performed"` if the last step would move real money. `store` raw + `sanitize.summarize_txn` in notes. Library: `references/logic-scenarios.md`.

## Validate (triage-validation gate) — KILL if
- The "abuse" needs an **unrealistic precondition** (admin already, victim self-attacks, impossible state).
- **No real gain** — no money/data/privilege actually changes hands; just a cosmetic/echo difference.
- It's **intended behavior** (documented discount, allowed free tier, refundable by policy).
- Only self-impact with no cost to the business.

## Done
Concrete, attacker-attainable harm **quantified** ($, records, or privilege), reproducible from a clean session with the exact request sequence. `confirmed`, `severity`, `proof_note`, one business-impact line (e.g. "buy any item for $0 via price tamper at confirm step").

## references/
`references/logic-scenarios.md` — the scenario library (one line each).
