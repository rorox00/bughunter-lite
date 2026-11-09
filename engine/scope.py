# engine/scope.py
"""Deterministic, DENY-WINS, default-deny scope allowlist.

This module is the project's safety boundary. It is pure code with no network
access. A host is in scope only if it matches the in_scope allowlist AND does
not match the out_of_scope denylist; anything unmatched is denied.

Host extraction uses urllib.parse.urlsplit so ports, IPv6 literals ([::1]) and
userinfo tricks (http://in-scope@evil/) resolve to the real connection host.
IP/CIDR matching is driven by the ipaddress module so IPv4 and IPv6 networks
are both handled without fragile regexes.
"""

import argparse
import ipaddress
import json
import urllib.parse


def _host_of(s):
    """Return the bare lowercase hostname of a URL or host string.

    Strips scheme, path, port and userinfo. Returns "" when nothing usable is
    found. A scheme-less string is treated as a host by prepending http://.
    """
    s = (s or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        return (urllib.parse.urlsplit(s).hostname or "").lower()
    except ValueError:
        return ""


def _clean(items):
    """Lowercase and strip entries, dropping empties."""
    return [x.strip().lower() for x in (items or []) if x and x.strip()]


class Scope:
    """A default-deny allowlist of hosts, wildcards and CIDRs."""

    def __init__(self, name, in_scope, out_of_scope, seeds):
        self.name = (name or "").strip()
        self.in_scope = _clean(in_scope)
        self.out_of_scope = _clean(out_of_scope)
        self.seeds = _clean(seeds)

    @classmethod
    def load(cls, path):
        """Build a Scope from a JSON file {name, in_scope, out_of_scope, seeds}."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        scope = cls(
            name=data.get("name", ""),
            in_scope=data.get("in_scope"),
            out_of_scope=data.get("out_of_scope"),
            seeds=data.get("seeds"),
        )
        if not scope.in_scope:
            raise ValueError("in_scope must list at least one host/wildcard/CIDR")
        if not scope.seeds:
            raise ValueError("seeds must list at least one start URL")
        return scope

    @staticmethod
    def _match_one(host, pattern):
        """Return True if a bare hostname matches a single scope pattern."""
        host = host.lower()
        pattern = pattern.lower()

        # IP / CIDR: only meaningful when the host itself is an IP address.
        try:
            ip = ipaddress.ip_address(host)
            try:
                return ip in ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                return False  # host is an IP, pattern is not a matching network
        except ValueError:
            pass

        # Wildcard: "*.acme.com" matches the apex and any subdomain.
        if pattern.startswith("*."):
            apex = pattern[2:]
            return host == apex or host.endswith("." + apex)

        # Bare apex: "acme.com" matches the apex and any subdomain (spec).
        if "." in pattern and "*" not in pattern:
            return host == pattern or host.endswith("." + pattern)

        # Anything else: exact string equality.
        return host == pattern

    def _matches_any(self, host, patterns):
        """True if _host_of(host) matches any of the given patterns."""
        h = _host_of(host)
        return any(self._match_one(h, p) for p in patterns)

    def in_scope_host(self, host_or_url):
        """Return True only if the host is allowed (deny wins, default-deny)."""
        h = _host_of(host_or_url)
        if not h:
            return False
        if self._matches_any(h, self.out_of_scope):
            return False
        return self._matches_any(h, self.in_scope)

    def filter_hosts(self, hosts):
        """Return the sorted set of in-scope bare hosts drawn from hosts."""
        result = set()
        for h in hosts:
            if self.in_scope_host(h):
                result.add(_host_of(h))
        return sorted(result)

    def __repr__(self):
        return "Scope(name=%r, in_scope=%r, out_of_scope=%r, seeds=%d)" % (
            self.name, self.in_scope, self.out_of_scope, len(self.seeds),
        )


def _selftest():
    """Offline asserts covering allow, deny-wins and default-deny."""
    s = Scope(
        name="sample",
        in_scope=["*.acme.com", "acme.io", "203.0.113.0/24"],
        out_of_scope=["blog.acme.com"],
        seeds=["https://app.acme.com/"],
    )
    assert s.in_scope_host("app.acme.com"), "subdomain of wildcard should be in"
    assert s.in_scope_host("acme.com"), "apex of wildcard should be in"
    assert s.in_scope_host("acme.io"), "bare apex should be in"
    assert s.in_scope_host("sub.acme.io"), "subdomain of bare apex should be in"
    assert s.in_scope_host("203.0.113.9"), "ip within CIDR should be in"
    assert not s.in_scope_host("blog.acme.com"), "deny must win over allow"
    assert not s.in_scope_host("acme.org"), "unlisted host is default-deny"
    assert not s.in_scope_host("evil.com"), "unlisted host is default-deny"
    # URL forms with scheme/port/path resolve to the bare host.
    assert s.in_scope_host("https://app.acme.com:443/login")
    assert _host_of("https://APP.acme.com:8080/x") == "app.acme.com"
    # userinfo trick: the real host is what counts, not the userinfo label.
    assert not s.in_scope_host("http://app.acme.com@evil.com/")
    assert s.in_scope_host("http://evil.com@app.acme.com/")
    assert s.filter_hosts(["app.acme.com", "evil.com", "acme.io", "acme.io"]) == \
        ["acme.io", "app.acme.com"]
    print("scope.py self-test: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deterministic default-deny scope allowlist.")
    parser.add_argument("--check-url", help="URL or host to test against a config")
    parser.add_argument("--config", help="path to a scope JSON config")
    parser.add_argument("--selftest", action="store_true", help="run offline self-test")
    args = parser.parse_args()

    if args.check_url:
        if not args.config:
            raise SystemExit("--check-url requires --config FILE")
        scope = Scope.load(args.config)
        h = _host_of(args.check_url)
        if scope.in_scope_host(args.check_url):
            print("IN-SCOPE   host=%s  (%s)" % (h, scope.name))
            raise SystemExit(0)
        print("OUT-OF-SCOPE  host=%s  (%s)" % (h, scope.name))
        raise SystemExit(2)

    _selftest()
