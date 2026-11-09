# engine/recon.py
"""Recon adapter for bughunter-lite.

A thin adapter over the bash collection pipeline (recon.sh -> jsdiscover.sh ->
jsanalyze.sh) with a pure-Python regex fallback for when those tools are
absent. Raw output stays on disk in the engagement directory (token-safe);
this module reads the files, enforces the deny-wins scope filter IN PYTHON
over every URL/host, redacts secret values (keeping type only), and returns the
engine's dict shape. The offline self-test touches no network.
"""

import glob
import json
import math
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

try:
    from scope import Scope  # noqa: F401  (standalone / engine-dir on path)
except ImportError:  # imported as part of a package or from another cwd
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scope import Scope  # noqa: F401

try:
    import requests
except ImportError:
    requests = None

UA = "bughunter-lite/0.2 (+authorized-testing)"

# REPO root = two dirs up from this file (engine/recon.py -> engine -> root).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Core tools whose absence triggers the pure-Python fallback.
CORE_TOOLS = ("httpx", "subfinder")

# Known-secret signatures for the pure-Python fallback (names only are kept).
_SECRET_REGEXES = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"][^'\"]{8,}")),
]

REDACTED = "[REDACTED - verify]"


# --- small helpers -------------------------------------------------------

def _host_of(u):
    """Bare lowercase host of a URL, or "" for a relative path."""
    if "://" not in (u or ""):
        # Bare host or relative path: treat a leading "/" as relative.
        if not u or u.startswith("/"):
            return ""
    return (urllib.parse.urlparse(u).hostname or "").lower()


def _read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except OSError:
        return []


def _write_lines(path, lines):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def _script(name):
    """Resolve a pipeline script: repo root first, then scripts/ subdir."""
    for cand in (os.path.join(ROOT, name), os.path.join(ROOT, "scripts", name)):
        if os.path.isfile(cand):
            return cand
    return os.path.join(ROOT, name)


def _tool(name):
    return shutil.which(name) is not None


def _core_tools_present():
    return all(_tool(t) for t in CORE_TOOLS)


def _run(script, *args, log=print):
    """Run a pipeline script if it exists on disk; never raise."""
    if os.path.isfile(script):
        log("[recon] run %s %s" % (os.path.basename(script), " ".join(args)))
        subprocess.run([script, *args], check=False)
        return True
    log("[recon] missing script: %s" % script)
    return False


# --- the security step ---------------------------------------------------

def _in_scope_url(scope, u):
    """Keep relative paths; otherwise require the host to pass the scope gate."""
    h = _host_of(u)
    if not h:
        return True
    return scope.in_scope_host(u)


def _redact_secrets(lines):
    """Turn raw secret detections into {type, value:'[REDACTED - verify]'}.

    Values are never carried through; only the detector/type survives, deduped.
    """
    out, seen = [], set()
    for ln in lines:
        typ = "unknown"
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                typ = (obj.get("DetectorName") or obj.get("detector")
                       or obj.get("kind") or obj.get("type")
                       or obj.get("name") or "unknown")
        except (ValueError, TypeError):
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*[:=]", ln)
            if m:
                typ = m.group(1)
        typ = str(typ)
        if typ not in seen:
            seen.add(typ)
            out.append({"type": typ, "value": REDACTED})
    return out


def _shannon(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _high_entropy_count(strings, min_len=20, min_entropy=3.0):
    """Count distinct high-entropy tokens without storing any of their values."""
    seen = set()
    for s in strings:
        for tok in re.split(r"[^A-Za-z0-9_\-+/=.]+", s or ""):
            if len(tok) >= min_len and _shannon(tok) >= min_entropy:
                seen.add(tok)
    return len(seen)


def _build_result(scope, seed, out_dir):
    """Read pipeline outputs, apply the scope filter + redaction, shape the dict."""
    urls = _read_lines(os.path.join(out_dir, "urls.txt"))
    endpoints = _read_lines(os.path.join(out_dir, "endpoints.txt"))
    params = _read_lines(os.path.join(out_dir, "params.txt"))
    jsfiles = _read_lines(os.path.join(out_dir, "jsfiles.txt"))
    tech = _read_lines(os.path.join(out_dir, "tech.txt"))
    secret_lines = _read_lines(os.path.join(out_dir, "secrets.txt"))

    # SECURITY: deny-wins scope filter over every URL/host.
    urls = sorted({u for u in urls if _in_scope_url(scope, u)})
    endpoints = sorted({e for e in endpoints if _in_scope_url(scope, e)})
    js_files = sorted({u for u in jsfiles if _in_scope_url(scope, u)})
    params = sorted(set(params))
    tech = sorted({t.lower() for t in tech})

    inline_js_blocks = len(glob.glob(os.path.join(out_dir, "js", "inline_*.js")))

    return {
        "seed": seed,
        "host": _host_of(seed),
        "status": 200 if (urls or endpoints or js_files) else None,
        "tech": tech,
        "js_files": js_files,
        "inline_js_blocks": inline_js_blocks,
        "endpoints": endpoints,
        "params": params,
        "secrets": _redact_secrets(secret_lines),
        "high_entropy": _high_entropy_count(secret_lines + params + endpoints),
        "out_dir": out_dir,
    }


# --- pure-Python fallback (network; never exercised by the self-test) -----

def _http_get(url, timeout=20):
    """Single best-effort GET returning (status, text); never raises."""
    try:
        if requests is not None:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": UA})
            return r.status_code, r.text[:500000]
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read(500000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - recon must survive any network error
        return None, ""


def _python_recon(scope, seed, out_dir, log=print):
    """Zero-tool recon: fetch the seed, mine JS/endpoints, write pipeline files."""
    os.makedirs(os.path.join(out_dir, "js"), exist_ok=True)
    _, html = _http_get(seed)

    js_urls = {urllib.parse.urljoin(seed, m) for m in
               re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)}

    inline = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.I | re.S)
    for i, blk in enumerate(inline, 1):
        if blk.strip():
            _write_lines(os.path.join(out_dir, "js", "inline_%d.js" % i), [blk])

    corpus = html + "\n" + "\n".join(inline)
    for ju in list(js_urls):
        if scope.in_scope_host(ju):
            _, jtext = _http_get(ju)
            corpus += "\n" + jtext

    endpoints = set(re.findall(r'["\'](/[A-Za-z0-9_./-]{2,}|https?://[^"\'\s]+)["\']', corpus))
    params = set(re.findall(r'[?&]([A-Za-z0-9_-]{2,40})=', corpus))
    tech = set(re.findall(r'(?i)\b(react|angular|vue|next|nuxt|webpack|graphql|apollo|svelte|jquery)\b', corpus))
    secrets = [name for name, rx in _SECRET_REGEXES if rx.search(corpus)]

    _write_lines(os.path.join(out_dir, "live.txt"), [seed])
    _write_lines(os.path.join(out_dir, "urls.txt"),
                 sorted({seed} | {e for e in endpoints if e.startswith("http")}))
    _write_lines(os.path.join(out_dir, "endpoints.txt"), sorted(endpoints))
    _write_lines(os.path.join(out_dir, "params.txt"), sorted(params))
    _write_lines(os.path.join(out_dir, "jsfiles.txt"), sorted(js_urls))
    _write_lines(os.path.join(out_dir, "tech.txt"), sorted(t.lower() for t in tech))
    _write_lines(os.path.join(out_dir, "secrets.txt"), secrets)
    log("[recon] python fallback complete for %s" % seed)


# --- public entrypoint ----------------------------------------------------

def recon(scope, log=print):
    """Run recon for every in-scope seed; return a list of result dicts."""
    base = (os.environ.get("BH_RECON_OUT")
            or os.path.join(os.path.expanduser("~/.bughunter-lite"), "recon"))
    results = []
    for seed in scope.seeds:
        if not scope.in_scope_host(seed):
            log("[recon] skip out-of-scope seed: %s" % seed)
            continue
        domain = _host_of(seed) or re.sub(r"[^A-Za-z0-9_.-]", "_", seed)
        out_dir = os.path.join(base, domain)
        os.makedirs(os.path.join(out_dir, "js"), exist_ok=True)

        recon_sh = _script("recon.sh")
        if os.path.isfile(recon_sh) and _core_tools_present():
            _run(recon_sh, domain, out_dir, log=log)
            _run(_script("jsdiscover.sh"),
                 os.path.join(out_dir, "jsfiles.txt"),
                 os.path.join(out_dir, "live.txt"), out_dir, log=log)
            _run(_script("jsanalyze.sh"), out_dir, out_dir, log=log)
        else:
            log("[recon] scripts/core tools unavailable -> pure-Python fallback")
            _python_recon(scope, seed, out_dir, log=log)

        results.append(_build_result(scope, seed, out_dir))
    return results


if __name__ == "__main__":
    import tempfile

    scope = Scope(
        name="t",
        in_scope=["*.example.com"],
        out_of_scope=["blog.example.com"],
        seeds=["https://app.example.com/"],
    )

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = os.path.join(tmp, "app.example.com")
        os.makedirs(os.path.join(out_dir, "js"), exist_ok=True)

        _write_lines(os.path.join(out_dir, "urls.txt"), [
            "https://app.example.com/login",
            "https://evil.com/phish",
        ])
        _write_lines(os.path.join(out_dir, "endpoints.txt"), [
            "/api/v1/users",
            "https://app.example.com/api/v2/orders",
            "https://evil.com/steal",            # out-of-scope -> dropped
            "https://blog.example.com/post",     # deny-wins   -> dropped
        ])
        _write_lines(os.path.join(out_dir, "jsfiles.txt"), [
            "https://cdn.example.com/app.js",     # wildcard subdomain -> kept
            "https://evil.com/x.js",              # dropped
        ])
        _write_lines(os.path.join(out_dir, "params.txt"), ["id", "token", "id"])
        _write_lines(os.path.join(out_dir, "tech.txt"), ["React", "webpack"])
        _SECRET_VALUE = "Zx9Qw3Rp7Lk2Mn8Vb4Tc6Yd1Hj5Gf0"  # high-entropy, must not leak
        _write_lines(os.path.join(out_dir, "secrets.txt"), [
            '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE"}',
            "generic_api_key: " + _SECRET_VALUE,
        ])
        _write_lines(os.path.join(out_dir, "js", "inline_1.js"), ["var x=1;"])

        res = _build_result(scope, "https://app.example.com/", out_dir)

        # Scope filter dropped out-of-scope + denied hosts.
        assert res["endpoints"] == ["/api/v1/users",
                                    "https://app.example.com/api/v2/orders"], res["endpoints"]
        assert res["js_files"] == ["https://cdn.example.com/app.js"], res["js_files"]
        assert "urls" not in res  # urls is internal (used only for status), not in the shape
        # Shape + redaction.
        assert res["host"] == "app.example.com"
        assert res["status"] == 200
        assert res["tech"] == ["react", "webpack"]
        assert res["params"] == ["id", "token"]
        assert res["inline_js_blocks"] == 1
        assert {s["value"] for s in res["secrets"]} == {REDACTED}
        assert {s["type"] for s in res["secrets"]} == {"AWS", "generic_api_key"}
        assert res["high_entropy"] >= 1
        # The raw secret value must never appear anywhere in the result.
        assert _SECRET_VALUE not in json.dumps(res)
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(res)

    print("recon.py self-test: PASS")
