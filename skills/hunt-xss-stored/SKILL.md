---
name: hunt-xss-stored
description: Stored/persistent XSS - attacker input saved server-side and executed later in another user's browser. Use when input is persisted and rendered to others (profile fields, comments, filenames, support tickets, display names). Triggers - stored xss, persistent xss, second-order xss, admin-panel xss. Siblings - hunt-xss-reflected, hunt-xss-dom, hunt-xss-blind.
---

# hunt-xss-stored
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Input that is saved and later shown to OTHER users: profile/bio/display-name fields, comments/reviews, support tickets and their admin view, uploaded filenames/metadata, team/org names, webhook labels — anything that surfaces on someone else's page (especially a staff/admin panel).

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated, read-only.
2. As the **attacker** identity (`state.set_session("attacker", ...)`), store a **unique benign marker** (e.g. `bhl9173x`) in each candidate field.
3. Switch identity: load the page where it renders as a **different** session (`state.set_session("viewer", ...)`, request via `http` with that session). Confirm the marker is actually persisted and served to the viewer.
4. `diffr.diff(viewer_baseline, viewer_with_marker)` to see the stored value rendered; determine context (HTML/attr/JS) and confirm it is **unencoded** there.
5. Build the minimal **executing** PoC (DOM marker / benign `alert`) and verify it fires in the viewer context — note if the high-value sink is an admin/staff view. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The value is **encoded/escaped on output** for its render context (stored but inert).
- **Only you** see it — it is not stored for / served to other users (then it's self-XSS, not stored).
- Rendered in a **non-executing** context (shown as text, in a download, or never parsed as markup).

## Done
A PoC that fires for a **DIFFERENT** user (ideally a staff/admin viewer), with the store request, the render location, and the viewing identity. `confirmed`, `severity`, `proof_note`, one impact line (e.g. "any attacker's comment runs script in every reader's / the admin's session").
