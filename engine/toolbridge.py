# engine/toolbridge.py
"""Local fuzzer bridge for bughunter-lite.

Runs external fuzzers (ffuf, nuclei) and returns ONLY the anomalies worth a
human's attention. The scope guard runs BEFORE any process is spawned, so an
out-of-scope target never reaches a tool. Missing tools degrade to a safe
"not installed" result. No network of its own.
"""

import json
import os
import shutil
import subprocess
import tempfile
import urllib.parse
from collections import Counter


def have(tool):
    """True if `tool` is on PATH."""
    return shutil.which(tool) is not None


def _host(url):
    """Lowercase hostname of a URL."""
    return (urllib.parse.urlparse(url).hostname or "").lower()


def _guard(url, scope):
    """Refuse an out-of-scope target before spawning anything."""
    if scope and not scope.in_scope_host(url):
        raise ValueError("toolbridge: refusing out-of-scope target %s" % url)


def ffuf(url, wordlist, scope=None, extra=None, timeout=300, filter_mode="auto"):
    """Run ffuf and return non-baseline hits only.

    In "auto" filter mode the single most common (status, length) pair — the
    catch-all/baseline response — is dropped so only anomalies remain.
    """
    _guard(url, scope)
    if "FUZZ" not in url:
        raise ValueError("toolbridge: ffuf url must contain FUZZ: %s" % url)
    if not have("ffuf"):
        return {"tool": "ffuf", "error": "ffuf not installed", "results": []}

    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
    os.close(fd)
    cmd = ["ffuf", "-u", url, "-w", wordlist,
           "-mc", "200,201,204,301,302,307,401,403,405,500",
           "-ac", "-t", "50", "-rate", "50", "-o", tmp, "-of", "json", "-s"]
    if extra:
        cmd += list(extra)
    try:
        subprocess.run(cmd, check=False, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(tmp, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (subprocess.TimeoutExpired, ValueError, OSError) as e:
        return {"tool": "ffuf", "error": str(e), "results": []}
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    results = []
    for r in (data.get("results") or []):
        inp = r.get("input")
        if isinstance(inp, dict):
            inp = inp.get("FUZZ") or next(iter(inp.values()), None)
        results.append({
            "input": inp,
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
        })

    if filter_mode == "auto" and results:
        counts = Counter((x["status"], x["length"]) for x in results)
        baseline = counts.most_common(1)[0][0]
        results = [x for x in results if (x["status"], x["length"]) != baseline]

    return {"tool": "ffuf", "error": None, "results": results[:200]}


def nuclei(url, scope=None, templates=None,
           severity="low,medium,high,critical", timeout=600):
    """Run nuclei and return parsed findings (capped at 200)."""
    _guard(url, scope)
    if not have("nuclei"):
        return {"tool": "nuclei", "error": "nuclei not installed", "results": []}

    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-severity", severity]
    if templates:
        cmd += ["-t", templates]
    try:
        proc = subprocess.run(cmd, check=False, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except subprocess.TimeoutExpired as e:
        return {"tool": "nuclei", "error": str(e), "results": []}

    results = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        info = obj.get("info") or {}
        results.append({
            "template": obj.get("template-id") or obj.get("templateID") or obj.get("template"),
            "severity": info.get("severity") or obj.get("severity"),
            "matched": obj.get("matched-at") or obj.get("matched") or obj.get("host"),
            "name": info.get("name"),
        })
        if len(results) >= 200:
            break
    return {"tool": "nuclei", "error": None, "results": results[:200]}


if __name__ == "__main__":
    class _StubScope:
        def in_scope_host(self, u):
            h = _host(u)
            return h == "example.com" or h.endswith(".example.com")

    stub = _StubScope()
    raised = False
    try:
        ffuf("https://evil.com/FUZZ", "/tmp/w", scope=stub)
    except ValueError as e:
        raised = "out-of-scope" in str(e)
    assert raised, "scope guard must block out-of-scope before spawning"

    print("toolbridge.py self-test: PASS (scope guard blocks out-of-scope)")
