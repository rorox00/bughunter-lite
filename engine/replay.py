# engine/replay.py
"""Generic cross-session replay for access-control testing.

Replays the SAME in-scope request under several identities (plus anonymous)
through a transport.ScopedSession and compares the responses to surface likely
broken object/function-level authorization. Read-only: it only observes. This
module performs no network I/O of its own.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from diffr import diff  # noqa: E402


def cross_session(http, url, sessions, method="GET", include_anon=True):
    """Replay one request under each identity, and optionally anonymously.

    http is a transport.ScopedSession; sessions is {name: {headers, cookies}}.
    Returns {"by_identity": {name: txn}, "anon": txn or None}.
    """
    by_identity = {}
    for name, sess in (sessions or {}).items():
        by_identity[name] = http.request(method, url, session=sess)
    anon = http.request(method, url, session=None) if include_anon else None
    return {"by_identity": by_identity, "anon": anon}


def authz_signal(matrix, owner, attacker):
    """Diff an attacker identity against the resource owner for authz leaks.

    Returns an error dict if either identity is missing. Otherwise returns the
    owner-vs-attacker diff (and owner-vs-anon when present) plus a heuristic
    likely_broken_authz flag: True when the attacker got a 200 that was not
    blocked AND either the JSON shape is unchanged or the body is ~identical
    to the owner's (text_similarity > 0.95). Operator verifies.
    """
    by_id = matrix.get("by_identity", {})
    if owner not in by_id:
        return {"error": "owner identity '%s' not in matrix" % owner}
    if attacker not in by_id:
        return {"error": "attacker identity '%s' not in matrix" % attacker}

    owner_txn = by_id[owner]
    attacker_txn = by_id[attacker]

    result = {
        "owner": owner,
        "attacker": attacker,
        "attacker_vs_owner": diff(owner_txn, attacker_txn),
    }
    anon_txn = matrix.get("anon")
    if anon_txn:
        result["anon_vs_owner"] = diff(owner_txn, anon_txn)

    d = result["attacker_vs_owner"]
    status_ok = attacker_txn.get("status") == 200 and not attacker_txn.get("blocked")
    structurally_same = not d["json_keys_added"] and not d["json_keys_removed"]
    sim = d.get("text_similarity")
    high_sim = sim is not None and sim > 0.95
    result["likely_broken_authz"] = bool(status_ok and (structurally_same or high_sim))
    return result


if __name__ == "__main__":
    import json

    body = json.dumps({"id": 1, "email": "owner@acme.com", "balance": 100})
    owner_txn = {"status": 200, "blocked": False, "resp_len": len(body),
                 "elapsed_ms": 50, "resp_body": body}
    attacker_txn = {"status": 200, "blocked": False, "resp_len": len(body),
                    "elapsed_ms": 55, "resp_body": body}
    matrix = {"by_identity": {"owner": owner_txn, "attacker": attacker_txn}, "anon": None}

    sig = authz_signal(matrix, "owner", "attacker")
    assert sig["likely_broken_authz"] is True, sig
    assert sig["attacker_vs_owner"]["json_keys_added"] == []

    # Missing identity surfaces an error, not a crash.
    assert "error" in authz_signal(matrix, "owner", "ghost")

    print("replay.py self-test: PASS (cross-session authz signal)")
