#!/usr/bin/env python3
# scripts/demo_local.py
"""Self-contained LIVE proof that the engine works (no external traffic).

Spins up a deliberately-vulnerable app on 127.0.0.1:<random> and runs the REAL
engine against it: recon mining, the scope gate (off-scope redirect blocked),
cross-session IDOR detection, and differential analysis. All traffic is to
loopback; NO_PROXY is set so nothing touches the outside world.
"""

import os
import sys
import json
import threading
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Keep every request on loopback and out of any configured proxy.
for _var in ("NO_PROXY", "no_proxy"):
    cur = os.environ.get(_var, "")
    os.environ[_var] = (cur + ",127.0.0.1,localhost,::1").lstrip(",")

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(os.path.dirname(HERE), "engine")
sys.path.insert(0, ENGINE)

import scope as scope_mod   # noqa: E402
import transport            # noqa: E402
import replay               # noqa: E402
import diffr                # noqa: E402
import recon as recon_mod   # noqa: E402


class Handler(BaseHTTPRequestHandler):
    """A tiny, deliberately-vulnerable app for the proof."""

    def log_message(self, *a):  # silence default stderr logging
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/":
            return self._send(200,
                '<html><body><h1>demo</h1>'
                '<script src="/static/app.js"></script>'
                '<a href="/go?next=http://evil.com/">leave</a>'
                '</body></html>')

        if path == "/static/app.js":
            return self._send(200, (
                'const API = "/api/v1";\n'
                'async function load(id) { return fetch(`${API}/invoices/${id}`); }\n'
                '// endpoints and params the crawler should mine:\n'
                'const a = "/api/v1/invoices/42";\n'
                'const b = "/api/v1/users/1";\n'
                'const c = "/orders?order_id=1&redirect_url=/dashboard";\n'
                'const d = "/go?next=/home";\n'
            ), "application/javascript")

        if path == "/go":
            # Open redirect off-scope; the engine must refuse to follow it.
            return self._send(302, "", "text/plain", {"Location": "http://evil.com/"})

        if path.startswith("/api/v1/invoices/"):
            raw = path.rsplit("/", 1)[-1] or "0"
            try:
                n = int(raw)
            except ValueError:
                n = 0
            # IDOR: identity in Authorization is IGNORED; any caller gets the record.
            return self._send(200, json.dumps({
                "id": n, "owner": "user%d" % n,
                "amount": 1000 + n, "ssn": "***-**-%04d" % (n % 10000),
            }), "application/json")

        if path == "/api/v1/users/1":
            return self._send(200, json.dumps(
                {"id": 1, "name": "alice", "role": "user"}), "application/json")

        return self._send(404, "not found", "text/plain")


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    scope = scope_mod.Scope("demo", ["127.0.0.1"], [], [base + "/"])
    noop = lambda *a, **k: None  # noqa: E731

    checks = []

    def check(name, cond):
        ok = bool(cond)
        checks.append(ok)
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
        return ok

    try:
        # 1) recon mines an invoices endpoint + the expected params.
        os.environ["BH_RECON_OUT"] = os.path.join(tempfile.mkdtemp(), "recon")
        results = recon_mod.recon(scope, log=noop)
        eps, params = set(), set()
        for r in results:
            eps |= set(r.get("endpoints") or [])
            params |= set(r.get("params") or [])
        check("recon mines 'invoices' endpoint + {order_id,redirect_url,next}",
              any("invoices" in e for e in eps)
              and {"order_id", "redirect_url", "next"} <= params)

        # 2) scope gate: off-scope redirect is blocked; in-scope root is 200.
        http = transport.ScopedSession(scope, log=noop)
        go = http.get(base + "/go?next=http://evil.com/")
        root = http.get(base + "/")
        check("off-scope redirect blocked (403) AND root 200 not blocked",
              go.get("status") == 403 and go.get("blocked")
              and root.get("status") == 200 and not root.get("blocked"))

        # 3) cross-session IDOR: two identities, same record -> broken authz.
        sessions = {
            "owner": {"headers": {"Authorization": "Bearer owner"}, "cookies": ""},
            "attacker": {"headers": {"Authorization": "Bearer attacker"}, "cookies": ""},
        }
        matrix = replay.cross_session(http, base + "/api/v1/invoices/42", sessions)
        sig = replay.authz_signal(matrix, "owner", "attacker")
        check("cross-session authz_signal -> likely_broken_authz",
              sig.get("likely_broken_authz") is True)

        # 4) differential analysis: /invoices/41 vs /42, both reachable.
        t41 = http.get(base + "/api/v1/invoices/41")
        t42 = http.get(base + "/api/v1/invoices/42")
        d = diffr.diff(t41, t42)
        check("diff invoices/41 vs /42 (both reachable)",
              t41.get("status") == 200 and not t41.get("blocked")
              and t42.get("status") == 200 and not t42.get("blocked")
              and isinstance(d, dict))
    finally:
        srv.shutdown()

    passed, total = sum(checks), len(checks)
    tag = "ENGINE WORKS" if passed == total else "ENGINE INCOMPLETE"
    print("RESULT: %d/%d checks passed -> %s" % (passed, total, tag))
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
