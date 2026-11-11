---
name: hunt-race-condition
description: Race condition (a business-logic sub-class) - a check-then-act window lets the same single-use/limited action succeed more times than allowed. Use on single-use or limited state changes (coupon redeem, withdraw/transfer, vote, invite accept, gift-card, trial start). Triggers - race condition, toctou, double spend, over-redemption, concurrent requests, limit bypass. Related - hunt-business-logic.
---

# hunt-race-condition
Authorized, in-scope, read-first where possible — this class is INTRUSIVE by nature. Deliverable = reproducible verification proof.

## Signal
Actions that should happen at most once / N times: coupon or voucher redeem, withdraw/transfer/payout, vote/like, invite or request accept, gift-card apply, trial/credit grant, "claim once" rewards, inventory reserve. A per-user or global limit guards the state.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated. Establish the intended limit and a clean baseline (one request = one effect).
2. Fire the **same** state-changing request **many times concurrently** (near-simultaneous / single-packet style) with the same valid session, to hit the check-then-act (TOCTOU) window before state settles.
3. Compare outcomes with `diffr.diff` / counts: redeemed > allowed, balance went negative, N duplicate resources created, limit exceeded. The signal is **over-effect vs the single-shot baseline**.
4. **Authorization + least impact**: only where the engagement authorizes it, and prefer **your own test objects** (your coupon, your balance, your invite). Use the **smallest** burst that proves the over-effect; stop immediately after. `proof_note` records exactly what state was changed and that it was minimal/reversible.
5. `store` raw (all concurrent txns) + `sanitize.summarize_txn` in notes; keep the counts.

## Validate (triage-validation gate) — KILL if
- Operations are **atomic / properly locked** (idempotency key, DB constraint, row lock) — concurrency yields exactly one effect.
- The "duplicate" is **expected** (the action is legitimately repeatable; no limit was meant to exist).
- The extra successes have **no real impact** (cosmetic, self-only, instantly reconciled/refunded).
- Apparent over-count is just retries you miscounted, not distinct committed effects.

## Done
Proof of over-redemption / double-spend / limit bypass with **counts** (e.g. "1 coupon redeemed 7× in a concurrent burst; balance credited 7×"), from a clean session, minimally demonstrated. `confirmed`, `severity`, `proof_note` (state touched + reversibility), one business-impact line.
