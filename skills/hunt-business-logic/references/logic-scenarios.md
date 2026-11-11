# Business-logic scenario library

A prompt list, one line each. Pick the flow that matches the target, model its
intended invariant, then break exactly one assumption and confirm real gain with
`diffr.diff`. Prove reachability read-only; never complete a real money move.

## Payment / checkout
- Price/amount tamper in the confirm request (client sends price → set it lower/0).
- Currency swap (pay 100 "weak-currency" units as if strong).
- Negative quantity → negative total → credit/refund to attacker.
- Decimal/precision abuse (0.001 rounds to 0; overflow to wraparound).
- Step-skip: jump to `/order/success` or `confirm` without a paid state.
- Reuse a completed payment token / idempotency key for a second order.
- Swap the paid item for a more expensive one after payment is authorized.

## Coupon / promo
- Replay a single-use coupon; stack multiple coupons; apply coupon post-total.
- Apply an expired/other-user/other-tier coupon by id.
- Referral self-redemption (invite yourself for credit).

## Refund / credit / wallet
- Refund more than paid; refund to a different account; double-refund.
- Transfer a negative amount (reverses direction); round-trip to mint value.
- Cancel-after-use (consume a service then cancel for a refund).

## Quota / limits / subscription
- Exceed a per-plan limit by tampering the tier/quota field in a later call.
- Downgrade after consuming an upgrade's benefits; keep premium features.
- Trial abuse: reset/replay the trial-start without re-verifying identity.

## Duplicate / idempotency
- Replay a create/claim request (missing idempotency) for N× the effect.
- Concurrent duplicate submit (if timing-sensitive → `hunt-race-condition`).

## Workflow / state machine
- Perform step B before required step A (approval before review, ship before pay).
- Re-open a closed/finalized object and re-act on it.
- Act on an object in a state your role should not be able to act on.

## Invite / referral / sharing
- Escalate an invite to a higher role than the inviter may grant.
- Accept an invite to an org/object you were never invited to (id swap → `hunt-idor`).

## Booking / inventory
- Hold/reserve beyond inventory; book a slot already taken; zero-cost hold loop.
- Cancel-and-rebook to dodge a fee or change price.

For each: the finding is the **quantified gain**, not the mere difference.
