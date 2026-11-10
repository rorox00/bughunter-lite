# engine/skill_map.py
"""Map the recon surface to installed hunt-* skills, each with a ready curl.

Takes recon.py result dicts (host, endpoints, params, secrets) and emits ranked
candidate dicts: which vuln class a path/param/secret suggests, which hunt-skill
covers it (flagged if not installed), and a full copy-paste curl. No network.
"""

import os
import re

# Vuln class -> priority weight (higher first).
CLASS_WEIGHT = {
    "rce": 100, "sqli": 90, "ssti": 88, "ssrf": 85, "auth-bypass": 85,
    "idor": 80, "lfi": 78, "xxe": 75, "forgot-password": 75, "cache-poison": 72,
    "file-upload": 68, "graphql": 65, "oauth": 62, "business-logic": 58,
    "race-condition": 58, "xss": 55, "cors": 45, "open-redirect": 40,
    "secret": 35, "info-leak": 30,
}

# Vuln class -> hunt skill(s). Secret/info-leak share hunt-source-leak.
CLASS_SKILL = {cls: ["hunt-%s" % cls] for cls in CLASS_WEIGHT}
CLASS_SKILL["secret"] = ["hunt-source-leak"]
CLASS_SKILL["info-leak"] = ["hunt-source-leak"]

# Parameter-name signals.
PARAM_SIGNALS = {
    "ssrf": re.compile(r"(url|uri|target|dest|redirect|callback|webhook|img|image|"
                       r"fetch|load|proxy|site|host|domain|feed)", re.I),
    "idor": re.compile(r"(^id$|_id$|^uid$|uuid|guid|account|order|invoice|number)", re.I),
    "open-redirect": re.compile(r"(redirect|return_url|returnurl|next|dest|goto|continue|url)", re.I),
    "lfi": re.compile(r"(file|path|filename|template|doc|document|page|folder|download|include|read)", re.I),
}

# URL-path signals.
PATH_SIGNALS = {
    "idor": re.compile(r"/(users?|orders?|invoices?|accounts?|customers?|profiles?|"
                       r"tickets?|messages?|documents?)/", re.I),
    "graphql": re.compile(r"/graphql", re.I),
    "auth-bypass": re.compile(r"/(admin|internal|debug|actuator|console|manage)", re.I),
    "lfi": re.compile(r"/(download|attachment|export|fetch|backup)(/|$|\?)", re.I),
    "secret": re.compile(r"\.(env|git|map|bak|old|json)$", re.I),
}

UA = "bughunter-lite/0.2"
SECRET_NOTE = "# manual verify only - do NOT exercise credentials; %d redacted secret(s) in evidence/"


def _resolve_skills_dir():
    """Return the skills directory: $CBH_SKILLS_DIR, else <repo>/skills, else ~/.claude/skills."""
    env = os.environ.get("CBH_SKILLS_DIR")
    if env:
        return env
    repo_skills = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills")
    if os.path.isdir(repo_skills):
        return repo_skills
    return os.path.expanduser("~/.claude/skills")


def installed_skills():
    """Return the set of installed skill names (empty set if the dir is missing)."""
    d = _resolve_skills_dir()
    try:
        return {name for name in os.listdir(d)
                if os.path.isdir(os.path.join(d, name))}
    except OSError:
        return set()


def _skills_for(cls, installed):
    """Resolve skills for a class, marking any that are not installed."""
    names = CLASS_SKILL.get(cls, ["hunt-%s" % cls])
    return [n if n in installed else "(missing:%s)" % n for n in names]


def _curl_for(cls, base, path, param=None):
    """Build a full copy-paste curl for a candidate target."""
    if path.startswith("http"):
        url = path
    else:
        url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
    if param:
        sep = "&" if "?" in url else "?"
        url = "%s%s%s=FUZZ" % (url, sep, param)
    return "curl -s -k -i -A '%s' -m 20 '%s'" % (UA, url)


def _add(cands, seen, host, where, param, cls, base, path, installed):
    """Append one deduped candidate (keyed by host/where/class)."""
    key = (host, where, cls)
    if key in seen:
        return
    seen.add(key)
    cands.append({
        "host": host,
        "where": where,
        "param": param,
        "class": cls,
        "weight": CLASS_WEIGHT.get(cls, 0),
        "skills": _skills_for(cls, installed),
        "curl": _curl_for(cls, base, path, param),
    })


def classify(recon_results, scope=None):
    """Turn recon results into ranked, deduped candidate dicts."""
    installed = installed_skills()
    cands, seen = [], set()
    for res in (recon_results or []):
        host = res.get("host") or ""
        if scope and host and not scope.in_scope_host(host):
            continue
        base = "https://" + host if host else ""

        for ep in (res.get("endpoints") or []):
            if scope and ep.startswith("http") and not scope.in_scope_host(ep):
                continue
            for cls, rx in PATH_SIGNALS.items():
                if rx.search(ep):
                    _add(cands, seen, host, ep, None, cls, base, ep, installed)

        for p in (res.get("params") or []):
            for cls, rx in PARAM_SIGNALS.items():
                if rx.search(p):
                    _add(cands, seen, host, "?" + p, p, cls, base, "/", installed)

        secs = res.get("secrets") or []
        if secs:
            key = (host, "secret", "secret")
            if key not in seen:
                seen.add(key)
                cands.append({
                    "host": host, "where": "secret", "param": None,
                    "class": "secret", "weight": CLASS_WEIGHT.get("secret", 0),
                    "skills": _skills_for("secret", installed),
                    "curl": SECRET_NOTE % len(secs),
                })

    cands.sort(key=lambda c: -c["weight"])
    return cands


def write_arsenal(candidates, path):
    """Write candidates as a markdown table and return the path."""
    lines = ["| wt | class | skill(s) | where | first curl |",
             "|----|-------|----------|-------|------------|"]
    for c in candidates:
        lines.append("| %d | %s | %s | %s | `%s` |" % (
            c["weight"], c["class"], ", ".join(c["skills"]), c["where"], c["curl"]))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


if __name__ == "__main__":
    demo = [{
        "host": "app.example.com",
        "endpoints": ["/api/v1/users/42", "/graphql", "/download"],
        "params": ["redirect_url", "order_id", "file"],
        "secrets": [{"type": "aws_access_key", "value": "[REDACTED - verify]"}],
    }]
    cands = classify(demo)

    print("%-3s %-13s %-28s %s" % ("wt", "class", "where", "skill(s)"))
    for c in cands:
        print("%-3d %-13s %-28s %s" % (
            c["weight"], c["class"], c["where"], ", ".join(c["skills"])))

    classes = {c["class"] for c in cands}
    assert "ssrf" in classes, "redirect_url should signal ssrf"
    assert "idor" in classes, "/users/ path and order_id param should signal idor"
    assert "graphql" in classes, "/graphql should signal graphql"
    assert "lfi" in classes, "file param / download path should signal lfi"
    assert "secret" in classes, "a secret should emit a secret candidate"
    # Sorted by descending weight.
    assert all(cands[i]["weight"] >= cands[i + 1]["weight"] for i in range(len(cands) - 1))
    # The secret candidate never exercises credentials.
    sec = next(c for c in cands if c["class"] == "secret")
    assert "do NOT exercise" in sec["curl"]

    print("skill_map.py self-test: PASS")
