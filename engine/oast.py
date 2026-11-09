# engine/oast.py
"""OAST (out-of-band application security testing) for bughunter-lite.

Thin wrapper around ProjectDiscovery's interactsh-client for catching blind
SSRF/RCE callbacks. If the binary is absent, every method degrades to a safe
no-op so the engine keeps working. The offline self-test touches no network.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid

INSTALL_HINT = ("interactsh-client not found; install: go install "
                "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")


class Oast:
    """Manage an interactsh-client session and poll for interactions."""

    def __init__(self, log=print, server=None):
        self.log = log
        self.server = server
        self.proc = None
        self.file = None
        self.path = None
        self.base = None

    def available(self):
        """True if the interactsh-client binary is on PATH."""
        return shutil.which("interactsh-client") is not None

    def start(self, timeout=15):
        """Launch interactsh-client and capture the registered OAST domain.

        Returns False (and logs an install hint) if the binary is missing or no
        domain registers within `timeout` seconds; True once *.base is ready.
        """
        if not self.available():
            self.log(INSTALL_HINT)
            return False

        fd, self.path = tempfile.mkstemp(suffix=".jsonl", prefix="oast_")
        os.close(fd)

        cmd = ["interactsh-client", "-json", "-o", self.path]
        if self.server:
            cmd += ["-server", self.server]
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        deadline = time.time() + timeout
        while time.time() < deadline and self.base is None:
            line = self.proc.stdout.readline()
            if not line:
                if self.proc.poll() is not None:
                    break
                continue
            for tok in line.split():
                t = tok.strip().strip('"').rstrip("/")
                if "://" in t:
                    t = t.split("://", 1)[1]
                t = t.strip().lower()
                if "." in t and "oast" in t:
                    self.base = t
                    break

        self.file = open(self.path, "r", encoding="utf-8", errors="replace")
        if self.base:
            self.log("ready: *.%s" % self.base)
            return True
        self.log("interactsh-client did not register a domain within %ds" % timeout)
        return False

    def new_url(self, label=None):
        """Return a fresh OAST hostname '<label-or-rand>.<base>', or None."""
        if not self.base:
            return None
        lab = label or uuid.uuid4().hex[:10]
        return ("%s.%s" % (lab, self.base)).lower()

    def poll(self, contains=None):
        """Read any new interactions from the jsonl log, optionally filtered."""
        out = []
        if not self.file:
            return out
        while True:
            line = self.file.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            if contains and contains not in line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            out.append({
                "protocol": obj.get("protocol"),
                "remote": obj.get("remote-address") or obj.get("remote_addr"),
                "full_id": obj.get("full-id") or obj.get("unique-id"),
                "ts": obj.get("timestamp"),
            })
        return out

    def stop(self):
        """Terminate the client process and close the log file."""
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:  # noqa: BLE001 - cleanup must never raise
                pass
            self.proc = None
        if self.file:
            try:
                self.file.close()
            except Exception:  # noqa: BLE001
                pass
            self.file = None


if __name__ == "__main__":
    o = Oast()
    print("interactsh-client available:", o.available())
    print("oast.py self-test: PASS (no-op if binary missing)")
