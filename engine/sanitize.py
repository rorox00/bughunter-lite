# engine/sanitize.py
"""Token/context management for bughunter-lite.

Pure text functions that shrink raw HTTP dumps into compact, model-friendly
summaries so a full response body is never fed to the model. No network.
"""

import json
import re

# Request/response headers that are noise for analysis and get dropped.
NOISE_HEADERS = {
    "user-agent", "accept", "accept-language", "accept-encoding",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    "upgrade-insecure-requests", "dnt", "connection", "cache-control",
    "pragma", "cookie",
}

# Headers we always keep (matched by exact name or prefix, e.g. x-ratelimit-*).
KEEP_HEADER_HINTS = {
    "content-type", "location", "server", "x-powered-by", "set-cookie",
    "www-authenticate", "access-control-allow-origin", "x-ratelimit",
    "content-length", "x-request-id",
}

RE_DATA_URI = re.compile(r"data:[^\s'\"<>]+", re.IGNORECASE)
RE_SVG = re.compile(r"<svg\b.*?</svg>", re.IGNORECASE | re.DOTALL)
RE_STYLE = re.compile(r"<style\b.*?</style>", re.IGNORECASE | re.DOTALL)
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")

_OMIT = "[...omitted]"


def strip_boilerplate(body, max_len=4000):
    """Replace heavy inline assets with markers, collapse whitespace, elide.

    data: URIs, inline SVG/style blocks and long base64 runs become markers.
    If the result still exceeds max_len, keep the first and last halves with a
    "…[N chars elided]…" marker between them. Empty input returns "".

    Large inputs are pre-sliced to a bounded buffer before any regex runs, so a
    multi-megabyte body neither allocates giant intermediate strings nor risks
    catastrophic regex backtracking (ReDoS). The final output is identical for
    inputs within the buffer; only the discarded middle of huge inputs differs.
    """
    if not body:
        return ""
    # Pre-slice: regexes never need more than a local buffer around the edges.
    buffer_limit = max_len * 4
    if len(body) > buffer_limit:
        body = body[:max_len * 2] + " " + body[-max_len * 2:]
    s = RE_DATA_URI.sub(_OMIT, body)
    s = RE_SVG.sub(_OMIT, s)
    s = RE_STYLE.sub(_OMIT, s)
    s = RE_BASE64.sub(_OMIT, s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        half = max_len // 2
        elided = len(s) - 2 * half
        s = s[:half] + "…[%d chars elided]…" % elided + s[-half:]
    return s


def strip_headers(headers, keep_noise=False):
    """Return a filtered copy of headers.

    A cookie header is replaced with a presence marker. Otherwise a header is
    kept when keep_noise is set, when it matches KEEP_HEADER_HINTS, or when it
    is not in NOISE_HEADERS.
    """
    out = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk == "cookie":
            out["cookie"] = "[present, hidden]"
            continue
        if keep_noise:
            out[k] = v
            continue
        keep = any(lk == h or lk.startswith(h) for h in KEEP_HEADER_HINTS)
        if keep or lk not in NOISE_HEADERS:
            out[k] = v
    return out


def _shape(value, depth):
    """Return the structural shape of a JSON value, bounded in depth/width."""
    if depth >= 4:
        return "…"
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= 40:
                out["…"] = "<%d more keys>" % (len(value) - 40)
                break
            out[k] = _shape(v, depth + 1)
        return out
    if isinstance(value, list):
        if not value:
            return ["<list len=0>"]
        return ["<list len=%d>" % len(value), _shape(value[0], depth + 1)]
    return type(value).__name__


def structural_summary(body):
    """Return the JSON shape of body, or None if it is not JSON."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    return _shape(data, 0)


def _host_of(u):
    """Bare lowercase host from a URL string (regex-only, no urllib)."""
    u = u or ""
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", u)
    return u.split("/", 1)[0].split(":", 1)[0].lower()


def summarize_txn(txn, body_max=1500):
    """Return a compact, model-ready summary of a transaction dict."""
    redirects = []
    for hop in (txn.get("redirect_chain") or []):
        to = hop.get("to") if isinstance(hop, dict) else hop
        if to:
            redirects.append(_host_of(to))

    resp_body = txn.get("resp_body") or ""
    shape = structural_summary(resp_body)
    resp_shape = shape if shape is not None else strip_boilerplate(resp_body, body_max)

    return {
        "method": txn.get("method"),
        "url": txn.get("final_url") or txn.get("url"),
        "status": txn.get("status"),
        "blocked": txn.get("blocked"),
        "note": txn.get("note"),
        "resp_len": txn.get("resp_len"),
        "elapsed_ms": txn.get("elapsed_ms"),
        "redirects": redirects,
        "resp_headers": strip_headers(txn.get("resp_headers") or {}),
        "resp_shape": resp_shape,
    }


if __name__ == "__main__":
    # structural_summary types + list marker.
    body = json.dumps({
        "user": {"id": 1, "name": "alice", "token": "abc"},
        "roles": ["admin", "user"],
        "active": True,
    })
    shape = structural_summary(body)
    assert shape["user"]["id"] == "int"
    assert shape["user"]["name"] == "str"
    assert shape["user"]["token"] == "str"
    assert shape["roles"][0] == "<list len=2>"
    assert shape["roles"][1] == "str"
    assert shape["active"] == "bool"
    assert structural_summary("not json at all") is None

    # strip_boilerplate collapses a long base64 run.
    blob = "A" * 160
    cleaned = strip_boilerplate("start " + blob + " end")
    assert _OMIT in cleaned
    assert blob not in cleaned

    # strip_headers keeps Content-Type, hides Cookie, drops User-Agent.
    sh = strip_headers({
        "Content-Type": "application/json",
        "Cookie": "sid=1",
        "User-Agent": "x",
    })
    assert sh.get("Content-Type") == "application/json"
    assert sh.get("cookie") == "[present, hidden]"
    assert "User-Agent" not in sh

    print("sanitize.py self-test: PASS")
