# engine/diffr.py
"""Differential response analysis for bughunter-lite.

Compares a baseline transaction against a variant (e.g. an injected or
privilege-swapped request) and flags why the two differ: status, length,
timing, JSON structure/type shifts, and text similarity. No network.
"""

import difflib
import json


def _json(body):
    """Parse a response body as JSON, returning the object or None."""
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def _keys(obj, prefix=""):
    """Return the set of dot-path keys in a JSON object.

    Dict keys become prefix.key and recurse; a non-empty list recurses into its
    first element with a "[]" segment appended to the prefix.
    """
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = prefix + "." + k if prefix else k
            out.add(path)
            out |= _keys(v, path)
    elif isinstance(obj, list) and obj:
        out |= _keys(obj[0], prefix + "[]")
    return out


def _types(obj, prefix=""):
    """Return {dot-path: type name} for every dict value in a JSON object."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = prefix + "." + k if prefix else k
            out[path] = type(v).__name__
            out.update(_types(v, path))
    elif isinstance(obj, list) and obj:
        out.update(_types(obj[0], prefix + "[]"))
    return out


def diff(baseline, variant, len_pct=0.15, time_ms=750):
    """Compare two transaction dicts and explain how/why they differ."""
    b_status, v_status = baseline.get("status"), variant.get("status")
    b_len = baseline.get("resp_len") or 0
    v_len = variant.get("resp_len") or 0
    b_time = baseline.get("elapsed_ms") or 0
    v_time = variant.get("elapsed_ms") or 0

    len_delta = v_len - b_len
    time_delta = v_time - b_time

    why = []
    if b_status != v_status:
        why.append("status changed %s -> %s" % (b_status, v_status))
    if b_len and abs(len_delta) / b_len >= len_pct:
        why.append("length changed by %d (%.0f%%)" % (len_delta, 100 * abs(len_delta) / b_len))
    if abs(time_delta) >= time_ms:
        why.append("timing delta %dms (possible blind/injection)" % time_delta)

    bj = _json(baseline.get("resp_body"))
    vj = _json(variant.get("resp_body"))
    json_keys_added, json_keys_removed, json_type_changed = [], [], []
    if bj is not None and vj is not None:
        bk, vk = _keys(bj), _keys(vj)
        json_keys_added = sorted(vk - bk)
        json_keys_removed = sorted(bk - vk)
        bt, vt = _types(bj), _types(vj)
        for k in sorted(set(bt) & set(vt)):
            if bt[k] != vt[k]:
                json_type_changed.append("%s: %s -> %s" % (k, bt[k], vt[k]))
        if json_keys_added:
            why.append("json keys added: %s" % ", ".join(json_keys_added))
        if json_type_changed:
            why.append("json types changed: %s" % ", ".join(json_type_changed))

    text_similarity = None
    bb, vb = baseline.get("resp_body"), variant.get("resp_body")
    if bb is not None and vb is not None:
        text_similarity = difflib.SequenceMatcher(None, bb[:20000], vb[:20000]).ratio()
        if text_similarity < 0.9:
            why.append("low text similarity %.2f" % text_similarity)

    return {
        "status": {"baseline": b_status, "variant": v_status, "changed": b_status != v_status},
        "length": {"baseline": b_len, "variant": v_len, "delta": len_delta},
        "timing_ms": {"baseline": b_time, "variant": v_time, "delta": time_delta},
        "json_keys_added": json_keys_added,
        "json_keys_removed": json_keys_removed,
        "json_type_changed": json_type_changed,
        "text_similarity": text_similarity,
        "why": why,
        "interesting": bool(why),
    }


if __name__ == "__main__":
    base = {
        "status": 200, "resp_len": 30, "elapsed_ms": 100,
        "resp_body": json.dumps({"id": 1, "name": "a"}),
    }
    var = {
        "status": 200, "resp_len": 60, "elapsed_ms": 120,
        "resp_body": json.dumps({"id": 1, "name": "a", "is_admin": True, "ssn": "x"}),
    }
    d = diff(base, var)
    assert d["interesting"], "privilege/PII leak must be interesting"
    assert "is_admin" in d["json_keys_added"], d["json_keys_added"]
    assert "ssn" in d["json_keys_added"], d["json_keys_added"]
    assert d["json_keys_removed"] == []
    assert d["status"]["changed"] is False
    print("diffr.py self-test: PASS ->", d["why"])
