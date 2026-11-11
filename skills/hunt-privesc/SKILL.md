---
name: hunt-privesc
description: Vertical privilege escalation / broken function-level authorization (BFLA) - a low-privilege user invokes an admin/role-gated function or grants themselves a higher role. Use on admin/role-gated functions and role/tier/tenant fields. Horizontal (same-level cross-user) access lives in hunt-idor. Triggers - privilege escalation, privesc, bfla, admin function, role tamper, mass assignment role, vertical privesc.
---

# hunt-privesc
Authorized, in-scope, read-first, non-destructive. Deliverable = reproducible verification proof.

## Signal
Role-gated surface: admin/management endpoints and actions (create/delete user, change role, settings, billing, impersonate), and privilege-bearing fields in requests — `is_admin`, `role`, `isStaff`, `tier`, `plan`, `permissions`, `tenant_id`, `groups`. Functions the UI only shows to admins.

## Method
1. Identities: `state.set_session("lowpriv", headers=/cookies=)` (your real low-priv account) and, if available, `("admin", ...)` as the behavioral reference. `http = transport.ScopedSession(scope, store=store)` — scope-gated.
2. **BFLA (call the function)**: as the low-priv session, invoke the admin FUNCTION directly (the endpoint the admin UI calls). Harvest admin operations from the JS bundle (`js-analyze`) when the UI hides them.
3. **Privilege-field tampering (mass assignment)**: on your own profile/settings PATCH/PUT, add `role`/`is_admin`/`tier`/`tenant_id` the client never sends, and check if it sticks.
4. **Confirm with the low-priv session**: `replay.cross_session`/`replay.authz_signal` — the privileged action must succeed under the **lowpriv** identity (not admin). Compare to the admin baseline and to a denied control with `diffr.diff`.
5. Read-only default: prove a privileged **read** or that the privileged write is reachable & unauthorized WITHOUT mutating prod — `proof_note:"intrusive, NOT performed"` for the actual escalation write. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The function **enforces role** (low-priv call → `401/403`).
- You were **already authorized** for that action (not an escalation).
- **No state change / no privileged read** achieved (200 but ignored field, empty, or your own non-privileged data).
- A reflected `role=admin` in the response that isn't actually honored server-side.

## Done
A **low-priv** session performing a privileged action or gaining a higher role, with the request + the proven effect (the admin-only data returned, or the role actually changed/reachable). `confirmed`, `severity`, `proof_note`, one impact line (e.g. "any user escalates to admin via role field in the profile-update request").
