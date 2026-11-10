# engine/agent.py
"""The single LLM seam for bughunter-lite, with two pluggable backends.

run_agent() dispatches on $BH_BACKEND: "claude" shells out to the Claude CLI
with a tight allowlist (curl/python3 plus the Burp MCP request tools), "openai"
POSTs to a chat-completions endpoint. Both return the same shape. extract_json()
recovers the last JSON object/array a model emitted. No network in the self-test.
"""

import json
import os
import re
import subprocess
import time
import urllib.request

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Tight tool allowlist handed to the Claude CLI.
ALLOWED = [
    "Bash(curl:*)", "Bash(python3:*)", "Read", "Grep", "Glob",
    "mcp__burp__send_http1_request", "mcp__burp__send_http2_request",
    "mcp__burp__generate_collaborator_payload",
    "mcp__burp__get_collaborator_interactions",
]

SYSTEM_PROMPT = (
    "You are a methodical web-security testing planner operating strictly within "
    "an authorized, in-scope engagement. Reason step by step about the target, "
    "propose only read-only or explicitly authorized checks, and never fabricate "
    "findings. End EVERY reply with a single ```json``` fenced block containing "
    "your structured output (an object or array)."
)

RE_JSON_FENCE = re.compile(r"```json\s*(.*?)```", re.DOTALL | re.IGNORECASE)
RE_ANY_FENCE = re.compile(r"```[a-zA-Z0-9]*\s*(.*?)```", re.DOTALL)


def _try_json(s):
    """Parse s as JSON, returning it only if it is an array or object."""
    try:
        v = json.loads(s)
    except (ValueError, TypeError):
        return None
    return v if isinstance(v, (list, dict)) else None


def extract_json(text):
    """Return the LAST valid JSON array/object from ```json blocks, then bare blocks."""
    if not text:
        return None
    for rx in (RE_JSON_FENCE, RE_ANY_FENCE):
        last = None
        for m in rx.finditer(text):
            obj = _try_json(m.group(1).strip())
            if obj is not None:
                last = obj
        if last is not None:
            return last
    return _try_json(text.strip())


def _run_claude(task, skills_on, model, max_turns, timeout):
    """Run the Claude CLI once and normalize its JSON output."""
    allowed = list(ALLOWED)
    if skills_on:
        allowed += ["Skill", "Write"]

    cmd = ["claude", "-p", task,
           "--permission-mode", "bypassPermissions",
           "--allowedTools", ",".join(allowed),
           "--max-turns", str(max_turns),
           "--output-format", "json"]
    if model:
        cmd += ["--model", model]
    mcp = os.path.join(_REPO, "engine", "burp-mcp.json")
    if os.path.isfile(mcp):
        cmd += ["--mcp-config", mcp, "--strict-mcp-config"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"result": None, "error": "claude CLI not found", "cost_usd": None}
    except subprocess.TimeoutExpired:
        return {"result": None, "error": "timeout", "cost_usd": None}

    raw = proc.stdout or ""
    low = raw.lower()
    if "usage limit" in low or "session limit" in low:
        return {"result": None, "error": "rate-limited", "cost_usd": None}

    try:
        data = json.loads(raw)
    except ValueError:
        err = proc.stderr.strip() if proc.returncode else None
        return {"result": raw.strip() or None, "error": err, "cost_usd": None}

    if isinstance(data, dict):
        result = data.get("result")
        cost = data.get("total_cost_usd") or data.get("cost_usd")
        err = "claude reported error" if data.get("is_error") else None
    else:
        result, cost, err = data, None, None

    if isinstance(result, str) and (
            "usage limit" in result.lower() or "session limit" in result.lower()):
        err = "rate-limited"
    return {"result": result, "error": err, "cost_usd": cost}


def _run_openai(task, model, timeout):
    """POST to an OpenAI-compatible chat-completions endpoint."""
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return {"result": None, "error": "OPENAI_API_KEY not set", "cost_usd": None}
    base = os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
    url = base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini",
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task},
        ],
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Authorization": "Bearer %s" % key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - network/HTTP errors returned, not raised
        return {"result": None, "error": str(e), "cost_usd": None}
    try:
        content = json.loads(body)["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        return {"result": None, "error": "bad response: %s" % e, "cost_usd": None}
    return {"result": content, "error": None, "cost_usd": None}


def run_agent(task, skills_on=False, model=None, max_turns=40, timeout=600):
    """Run the configured LLM backend; return {result,error,cost_usd,backend,duration_s}."""
    backend = (os.environ.get("BH_BACKEND") or "claude").lower()
    start = time.time()
    if backend == "openai":
        out = _run_openai(task, model, timeout)
    else:
        out = _run_claude(task, skills_on, model, max_turns, timeout)
    out["backend"] = backend
    out["duration_s"] = round(time.time() - start, 3)
    return out


if __name__ == "__main__":
    # Two json blocks: the LAST valid one wins.
    assert extract_json(
        'noise ```json\n{"x":1}\n``` mid ```json\n[1,2,3]\n``` end') == [1, 2, 3]
    # Bare fenced block (no language tag).
    assert extract_json('```\n{"y":2}\n```') == {"y": 2}
    # A plain json array fence.
    assert extract_json('```json [1,2] ```') == [1, 2]
    # Scalars in a fence are not objects/arrays -> ignored.
    assert extract_json('```json\n42\n```') is None
    # No JSON anywhere.
    assert extract_json("no json here") is None
    assert extract_json("") is None

    b = (os.environ.get("BH_BACKEND") or "claude").lower()
    print("agent.py self-test: PASS (backend=%s)" % b)
