# engine/store.py
"""SQLite transaction log for bughunter-lite.

Raw HTTP requests and responses are written to a SQLite database on disk so
that large bodies never have to live in the model context. No network access.
"""

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL,
  method TEXT,
  url TEXT,
  final_url TEXT,
  host TEXT,
  status INTEGER,
  blocked INTEGER,
  note TEXT,
  req_headers TEXT,
  req_body TEXT,
  resp_headers TEXT,
  resp_body TEXT,
  resp_len INTEGER,
  elapsed_ms INTEGER,
  redirect_chain TEXT
);
CREATE INDEX IF NOT EXISTS idx_txn_host ON transactions(host);
CREATE INDEX IF NOT EXISTS idx_txn_status ON transactions(status);
"""

# JSON-encoded columns, decoded again on read.
_JSON_FIELDS = ("req_headers", "resp_headers", "redirect_chain")


class TxnStore:
    """A SQLite-backed append log of HTTP transactions."""

    def __init__(self, path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # check_same_thread=False lets worker threads share one connection;
        # a busy timeout plus WAL avoids "database is locked" under contention.
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30.0)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def record(self, txn):
        """Insert one transaction dict and return its new rowid.

        Headers and redirect_chain are JSON-encoded; bodies are truncated to
        keep the database bounded; blocked is normalised to 1/0.
        """
        ts = txn.get("ts", time.time())
        req_body = (txn.get("req_body") or "")[:200000]
        resp_body = (txn.get("resp_body") or "")[:500000]
        blocked = 1 if txn.get("blocked") else 0
        cur = self.conn.execute(
            "INSERT INTO transactions ("
            "ts, method, url, final_url, host, status, blocked, note, "
            "req_headers, req_body, resp_headers, resp_body, resp_len, "
            "elapsed_ms, redirect_chain) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                ts,
                txn.get("method"),
                txn.get("url"),
                txn.get("final_url"),
                txn.get("host"),
                txn.get("status"),
                blocked,
                txn.get("note"),
                json.dumps(txn.get("req_headers") or {}),
                req_body,
                json.dumps(txn.get("resp_headers") or {}),
                resp_body,
                txn.get("resp_len"),
                txn.get("elapsed_ms"),
                json.dumps(txn.get("redirect_chain") or []),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def get(self, tid):
        """Return the transaction with id tid as a dict, or None."""
        cur = self.conn.execute("SELECT * FROM transactions WHERE id = ?", (tid,))
        row = cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in cur.description]
        rec = dict(zip(cols, row))
        for field in _JSON_FIELDS:
            if rec.get(field):
                try:
                    rec[field] = json.loads(rec[field])
                except (ValueError, TypeError):
                    pass
        return rec

    def recent(self, host=None, n=20):
        """Return up to n recent transactions (most recent first) as dicts."""
        if host:
            cur = self.conn.execute(
                "SELECT id FROM transactions WHERE host = ? ORDER BY id DESC LIMIT ?",
                (host, n),
            )
        else:
            cur = self.conn.execute(
                "SELECT id FROM transactions ORDER BY id DESC LIMIT ?", (n,)
            )
        ids = [r[0] for r in cur.fetchall()]
        return [self.get(i) for i in ids]

    def close(self):
        """Close the underlying database connection."""
        self.conn.close()


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        store = TxnStore(os.path.join(tmp, "db", "txns.sqlite"))

        tid = store.record({
            "method": "GET",
            "url": "https://app.acme.com/login",
            "final_url": "https://app.acme.com/login",
            "host": "app.acme.com",
            "status": 200,
            "req_headers": {"User-Agent": "bughunter-lite"},
            "resp_headers": {"Content-Type": "text/html"},
            "resp_body": "<html>ok</html>",
            "resp_len": 15,
            "elapsed_ms": 42,
            "redirect_chain": [],
        })

        rec = store.get(tid)
        assert rec is not None
        assert rec["status"] == 200
        assert rec["req_headers"] == {"User-Agent": "bughunter-lite"}
        assert rec["redirect_chain"] == []

        top = store.recent()
        assert top[0]["url"] == "https://app.acme.com/login"
        assert store.get(99999) is None

        store.close()

    print("store.py self-test: PASS")
