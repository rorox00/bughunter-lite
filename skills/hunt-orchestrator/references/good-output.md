# What "done" looks like

The yardstick for a finished phase. If your engagement does not look like this,
it is not done.

## Engagement directory tree

A complete engagement directory:

```
<base>/<engagement-name>/
├── state.json                 # resumable state: phase, targets, candidates, findings, validated
├── engine.log                 # append-only, timestamped log of every phase + action
├── arsenal.md                 # ranked candidate table (wt | class | skill | where | curl)
├── report.md                  # validated findings only, written last
└── evidence/
    ├── hunt-01-idor.md        # one file per hunt, NON-ZERO bytes
    ├── hunt-02-ssrf.md
    └── ...
```

Rules:

- Every file above exists. An empty `evidence/` means no hunting happened.
- Every evidence file is **non-zero bytes**. A zero-byte log is a failed step,
  not a clean one.
- `report.md` contains **only validated** findings; leads live in `arsenal.md`
  and `evidence/`, not in the report.

## What a good evidence file contains

`evidence/hunt-NN-<class>.md` must let someone reproduce the finding without
you present:

- **Exact request(s)** — the full command(s) actually sent, copy-pasteable
  (`curl -s -k -i -A 'bughunter-lite/0.2' -m 20 '<url>'`), including any
  headers/identities used. No placeholders.
- **Impact response excerpt** — the specific bytes that prove impact (the
  cross-user record, the leaked field, the reflected/executed payload), trimmed
  to what matters. Secrets stay redacted.
- **confirmed** — `true` only when observed, never assumed.
- **severity** — info / low / medium / high / critical, justified by real harm.
- **proof_note** — one or two sentences: what this proves and why it matters to
  a normal user.

A finding that cannot be rebuilt from its evidence file alone is not done.

## A good finding answers all 7 gate questions

A finding only counts when every answer is yes (or concretely stated):

1. **In scope?** The affected host is in the allowlist (`scope.in_scope_host`).
2. **Reachable by an attacker?** It works unauthenticated, or as a different
   user — not only from a privileged/insider position.
3. **Affects someone else?** The harm lands on a normal user or the business,
   not only on your own account/data.
4. **Concrete impact?** You can name the real-world harm in one sentence
   (account takeover, data exposure, fund movement, …) — not a best-practice nit.
5. **Reproducible?** The recorded request(s) reproduce it on demand, from the
   evidence file alone.
6. **Evidence captured?** Request + the response excerpt that proves impact are
   both saved, non-zero bytes.
7. **Proven in-scope?** Proving it required **no** out-of-scope request — the
   proof stops at the scope boundary.

Any "no" kills the finding (not the engagement): drop it and move to the next
candidate.
