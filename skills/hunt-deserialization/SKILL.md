---
name: hunt-deserialization
description: Insecure deserialization leading to object injection / RCE - a server deserializes attacker-controlled data (Java, PHP, .NET, Python pickle, Ruby, Node). Use when you see a serialized blob in a cookie/param/body/header. Triggers - deserialization, insecure deserialization, object injection, java serial, php object injection, pickle rce, viewstate, gadget chain. Related - hunt-rce.
---

# hunt-deserialization
Authorized, in-scope, read-first where possible — escalation is INTRUSIVE. Deliverable = reproducible verification proof.

## Signal
Serialized blobs in cookies/params/bodies/headers (see `references/deser-gadgets.md` for exact markers): Java `rO0AB`/`\xac\xed`, PHP `O:`/`a:`, .NET `ViewState`/`AAEAAAD`, Python pickle, Ruby Marshal `\x04\x08`, Node (node-serialize `_$$ND_FUNC$$_`). A base64 token that decodes to one of these is the tell.

## Method
1. `http = transport.ScopedSession(scope, store=store)` — scope-gated. Decode the blob and **identify the format/language**.
2. **Confirm it's deserialized**: a minimally malformed/benign-property-changed object should alter behavior (error vs normal, a changed field) — `diffr.diff(baseline, tampered)`. If tampering is ignored or it's treated as opaque text, it may not be deserialized (KILL).
3. **Signature check**: is the blob HMAC-signed/encrypted and verified (e.g. signed cookie, protected ViewState)? If a valid signature is required and you can't forge it, stop — not exploitable (KILL) unless the key is leaked (`hunt-source-leak`).
4. **Prove object injection read-only first**: a property-oriented gadget or a benign marker that shows the object graph is instantiated — before any code gadget.
5. **RCE escalation (only where authorized)**: use a gadget chain to trigger a **blind OOB** callback — `oast.new_url("deser")` via a DNS/HTTP gadget, confirmed with `oast.poll(contains="deser")`. Do NOT run commands, spawn shells, or destructive gadgets on prod — `proof_note:"RCE reachable via <gadget family>, callback only, no command run"`.
6. `store` raw + `sanitize.summarize_txn` in notes.

## Validate (triage-validation gate) — KILL if
- The blob is **signed/HMAC'd and verified** and you can't forge it (tamper → rejected).
- It is **not actually deserialized** (treated as opaque/validated data; tampering has no effect).
- **No usable gadget** on the classpath/runtime (object injects but nothing reachable escalates) — note severity accordingly.
- Decode looks serialized but the endpoint just stores/echoes it.

## Done
Proof of object injection or RCE reachability — a benign property-change effect, or an OOB callback from a gadget — minimal and non-destructive, with the crafted blob + the observed effect/callback. `confirmed`, `severity`, `proof_note` (gadget family, not exercised), one impact line.

## references/
`references/deser-gadgets.md` — per-language markers, ysoserial/gadget notes, OOB confirmation.
