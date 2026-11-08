# engine/transport.py
"""In-band scope gate for bughunter-lite.

Every HTTP request passes through ScopedSession, which enforces the scope
allowlist and a read-only method guard IN CODE before any byte goes on the
wire, and re-checks scope on every redirect hop so a redirect can never carry
the client off-scope. Uses requests if available, else urllib with
auto-redirect disabled.
"""

import os
import sys
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from scope import Scope
except ImportError:  # running from a different cwd / as a package
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scope import Scope

try:
    import requests
except ImportError:
    requests = None

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_REDIRECTS = 8
UA = "bughunter-lite/0.1 (+operator-in-the-loop)"


def _host(url):
    """Return the lowercase hostname of a URL."""
    return (urllib.parse.urlparse(url).hostname or "").lower()


class Blocked(Exception):
    """Raised in-code when a request is refused by the scope/method gate."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib handler that disables automatic redirect following."""

    def redirect_request(self, *args, **kwargs):
        return None


class ScopedSession:
    """An HTTP client that refuses out-of-scope and state-changing requests."""

    def __init__(self, scope, allow_intrusive=False, store=None, log=print,
                 timeout=20, verify=None):
        self.scope = scope
        self.allow_intrusive = allow_intrusive
        self.store = store
        self.log = log
        self.timeout = timeout

        if verify is None:
            verify = os.environ.get("BH_PROXY_INSECURE") != "1"
        self.verify = verify

        self.proxy = (os.environ.get("BH_PROXY")
                      or os.environ.get("HTTPS_PROXY")
                      or os.environ.get("HTTP_PROXY"))

        no_proxy = {"localhost", "127.0.0.1", "::1"}
        env_np = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
        for part in env_np.split(","):
            part = part.strip().lower()
            if part:
                no_proxy.add(part)
        self._no_proxy = no_proxy

    # --- gates ---------------------------------------------------------

    def _proxy_for(self, url):
        """Return a proxies dict, or None to go direct (so Burp never sees localhost)."""
        if not self.proxy:
            return None
        h = _host(url)
        for entry in self._no_proxy:
            e = entry.lstrip(".")
            if e and (h == e or h.endswith("." + e)):
                return None
        return {"http": self.proxy, "https": self.proxy}

    def _assert_in_scope(self, url):
        if not self.scope.in_scope_host(url):
            raise Blocked(
                "out-of-scope host '%s' - request dropped by scope gate" % _host(url))

    def _assert_method(self, method):
        if method not in SAFE_METHODS and not self.allow_intrusive:
            raise Blocked(
                "state-changing method %s refused (read-only; pass "
                "--allow-intrusive to permit)" % method)

    def _blocked_txn(self, method, url, note, redirect_chain=None):
        """Build, record and log a 403/blocked transaction, then return it."""
        txn = {
            "method": method, "url": url, "final_url": url, "host": _host(url),
            "status": 403, "blocked": True, "note": note,
            "req_headers": {}, "req_body": "", "resp_headers": {}, "resp_body": "",
            "resp_len": 0, "elapsed_ms": 0, "redirect_chain": redirect_chain or [],
        }
        if self.store is not None:
            txn["id"] = self.store.record(txn)
        self.log("BLOCKED %s %s :: %s" % (method, url, note))
        return txn

    # --- raw I/O -------------------------------------------------------

    def _raw(self, method, url, headers, body):
        """Perform ONE request with no auto-redirect; return a raw-result dict."""
        start = time.time()
        if requests is not None:
            resp = requests.request(
                method, url, headers=headers, data=body,
                proxies=self._proxy_for(url), verify=self.verify,
                allow_redirects=False, timeout=self.timeout,
            )
            elapsed = int((time.time() - start) * 1000)
            rh = {k.lower(): v for k, v in resp.headers.items()}
            return {"status": resp.status_code, "headers": rh,
                    "body": resp.text[:500000], "elapsed_ms": elapsed}

        # urllib fallback.
        proxies = self._proxy_for(url)
        handlers = [_NoRedirect(),
                    urllib.request.ProxyHandler(proxies if proxies else {})]
        if url.lower().startswith("https") and not self.verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)

        data = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            resp = opener.open(req, timeout=self.timeout)
            status = resp.getcode()
            raw = resp.read(500000)
            rh = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            status = e.code
            raw = e.read(500000) if hasattr(e, "read") else b""
            rh = {k.lower(): v for k, v in (e.headers or {}).items()}
        elapsed = int((time.time() - start) * 1000)
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else (raw or "")
        return {"status": status, "headers": rh,
                "body": text[:500000], "elapsed_ms": elapsed}

    # --- public API ----------------------------------------------------

    def request(self, method, url, headers=None, body=None, session=None):
        """Issue a scoped request, following in-scope redirects only."""
        method = method.upper()
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", UA)
        if session:
            for k, v in (session.get("headers") or {}).items():
                hdrs[k] = v
            if session.get("cookies"):
                hdrs["Cookie"] = session["cookies"]

        try:
            self._assert_method(method)
            self._assert_in_scope(url)
        except Blocked as e:
            return self._blocked_txn(method, url, str(e))

        redirect_chain = []
        cur_method, cur_url, cur_body = method, url, body
        for _ in range(MAX_REDIRECTS + 1):
            raw = self._raw(cur_method, cur_url, hdrs, cur_body)
            status = raw["status"]

            if status in (301, 302, 303, 307, 308):
                loc = raw["headers"].get("location")
                if loc:
                    next_url = urllib.parse.urljoin(cur_url, loc)
                    redirect_chain.append(
                        {"from": cur_url, "to": next_url, "status": status})
                    try:
                        self._assert_in_scope(next_url)
                    except Blocked as e:
                        return self._blocked_txn(
                            method, url,
                            "redirect %d -> %s" % (status, str(e)),
                            redirect_chain=redirect_chain,
                        )
                    if status == 303:
                        cur_method, cur_body = "GET", None
                    cur_url = next_url
                    continue

            resp_body = raw["body"]
            txn = {
                "method": method, "url": url, "final_url": cur_url,
                "host": _host(cur_url), "status": status, "blocked": False,
                "note": "", "redirect_chain": redirect_chain,
                "req_headers": hdrs, "req_body": cur_body or "",
                "resp_headers": raw["headers"], "resp_body": resp_body,
                "resp_len": len(resp_body), "elapsed_ms": raw["elapsed_ms"],
            }
            if self.store is not None:
                txn["id"] = self.store.record(txn)
            self.log("%s %s -> %d (%dB, %dms)" % (
                method, cur_url, status, txn["resp_len"], raw["elapsed_ms"]))
            return txn

        return self._blocked_txn(method, url, "too many redirects",
                                 redirect_chain=redirect_chain)

    def get(self, url, **kw):
        """Convenience wrapper for a GET request."""
        return self.request("GET", url, **kw)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    sc = Scope(name="t", in_scope=["*.example.com"], out_of_scope=[],
               seeds=["https://app.example.com/"])
    sess = ScopedSession(sc)

    # Out-of-scope host is dropped before any network I/O.
    t1 = sess.get("https://evil.com/")
    assert t1["blocked"] is True

    # State-changing method is refused before any network I/O.
    t2 = sess.request("POST", "https://app.example.com/x")
    assert t2["status"] == 403
    assert t2["blocked"] is True

    print("transport.py self-test: PASS (scope gate + read-only guard, no network)")
