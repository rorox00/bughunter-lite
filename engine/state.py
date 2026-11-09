# engine/state.py
"""Resumable engagement store for bughunter-lite.

An Engagement owns a directory on disk holding its JSON state, a log, an
evidence folder, and report/arsenal scratch files. State is persisted
atomically so a run can be stopped and resumed. A corrupt state file is backed
up rather than silently overwritten, so findings are never lost. No network.
"""

import json
import os
import tempfile
import time


class Engagement:
    """A single named engagement rooted at <base>/<name> on disk."""

    def __init__(self, base, name):
        self.name = name
        self.dir = os.path.join(os.path.expanduser(base), name)
        self.evidence = os.path.join(self.dir, "evidence")
        os.makedirs(self.evidence, exist_ok=True)

        self.state_path = os.path.join(self.dir, "state.json")
        self.log_path = os.path.join(self.dir, "engine.log")
        self.arsenal_path = os.path.join(self.dir, "arsenal.md")
        self.report_path = os.path.join(self.dir, "report.md")

        self.state = self._load()

    def _load(self):
        """Load state from disk; back up a damaged file instead of losing it."""
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (ValueError, OSError) as e:
                backup = "%s.corrupt.%d" % (self.state_path, int(time.time()))
                try:
                    os.rename(self.state_path, backup)
                    self.log("WARNING: corrupted state (%s); backed up to %s" % (e, backup))
                except OSError:
                    pass
        return {
            "name": self.name,
            "phase": None,
            "targets": [],
            "candidates": [],
            "findings": [],
            "created": time.time(),
        }

    def save(self):
        """Write state atomically via a unique temp file and os.replace."""
        self.state["updated"] = time.time()
        with tempfile.NamedTemporaryFile(
                "w", dir=self.dir, delete=False, encoding="utf-8") as tf:
            json.dump(self.state, tf, indent=2)
            tmp_path = tf.name
        os.replace(tmp_path, self.state_path)

    def set_phase(self, phase):
        """Record the current phase, persist, and log the transition."""
        self.state["phase"] = phase
        self.save()
        self.log("--- phase: %s ---" % phase)

    def log(self, msg):
        """Print a timestamped message and append it to engine.log."""
        line = "[%s] %s" % (time.strftime("%H:%M:%S", time.localtime()), msg)
        print(line)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def evidence_file(self, name, content):
        """Write content to evidence/<name> and return its path."""
        path = os.path.join(self.evidence, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content or "")
        return path

    # --- Dual-session support (used later for access-control testing) ---

    def set_session(self, name, headers=None, cookies="", note=""):
        """Store a named session (headers/cookies/note), persist, and log it."""
        self.state.setdefault("sessions", {})[name] = {
            "headers": headers or {},
            "cookies": cookies,
            "note": note,
        }
        self.save()
        self.log("session set: %s" % name)

    def get_session(self, name):
        """Return the named session dict, or None."""
        return self.state.get("sessions", {}).get(name)

    def sessions(self):
        """Return all stored sessions as a dict."""
        return self.state.get("sessions", {})


if __name__ == "__main__":
    import glob

    with tempfile.TemporaryDirectory() as tmp:
        eng = Engagement(tmp, "selftest")

        eng.set_phase("recon")
        assert eng.state["phase"] == "recon"

        ev_path = eng.evidence_file("note.txt", "hello evidence")
        assert os.path.exists(ev_path)
        with open(ev_path, "r", encoding="utf-8") as f:
            assert f.read() == "hello evidence"

        eng.set_session("userA", headers={"X-Token": "a"}, cookies="sid=1", note="low-priv")
        sess = eng.get_session("userA")
        assert sess is not None
        assert sess["headers"] == {"X-Token": "a"}
        assert sess["cookies"] == "sid=1"
        assert sess["note"] == "low-priv"
        assert "userA" in eng.sessions()
        assert eng.get_session("missing") is None

        # Reload from disk to prove persistence.
        reloaded = Engagement(tmp, "selftest")
        assert reloaded.state["phase"] == "recon"
        assert reloaded.get_session("userA") == sess

        # Corruption recovery: a damaged state.json is backed up, not lost.
        with open(reloaded.state_path, "w", encoding="utf-8") as f:
            f.write("{ this is not valid json ")
        recovered = Engagement(tmp, "selftest")
        assert recovered.state["phase"] is None, "should fall back to default state"
        assert glob.glob(reloaded.state_path + ".corrupt.*"), "corrupt backup must exist"

    print("state.py self-test: PASS")
