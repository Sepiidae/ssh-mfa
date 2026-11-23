"""SQLite-backed store.

Zero extra infrastructure: a single file on the target host (or on a shared
filesystem the auth server can write to). Uses a short-lived connection per
call so the many parallel AuthorizedKeysCommand invocations don't hold locks,
and ``busy_timeout`` so concurrent writers don't error on ``SQLITE_BUSY``.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Optional

from .base import Approval, Store, StoreError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    username    TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL,
    pubkey      TEXT    NOT NULL,
    identity    TEXT    NOT NULL,
    issued_at   REAL    NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 86400,
    challenge   TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (username, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_approvals_user ON approvals(username);
"""


class SqliteStore(Store):
    def __init__(self, path: str, ttl_default: int = 86400):
        self.path = path
        self.ttl_default = ttl_default
        self._local = threading.local()
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(_SCHEMA)
            self._local.conn = conn
        return conn

    def _init(self) -> None:
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.executescript(_SCHEMA)
        finally:
            conn.close()

    def grant(self, approval: Approval) -> None:
        a = approval
        if a.ttl_seconds <= 0:
            a.ttl_seconds = self.ttl_default
        self._conn().execute(
            """
            INSERT INTO approvals
                (username, fingerprint, pubkey, identity, issued_at,
                 ttl_seconds, challenge, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username, fingerprint) DO UPDATE SET
                pubkey=excluded.pubkey,
                identity=excluded.identity,
                issued_at=excluded.issued_at,
                ttl_seconds=excluded.ttl_seconds,
                challenge=excluded.challenge,
                source=excluded.source
            """,
            (a.username, a.fingerprint, a.pubkey, a.identity,
             a.issued_at, a.ttl_seconds, a.challenge, a.source),
        )
        self._conn().commit()

    def lookup(self, username: str, pubkey: str) -> Optional[Approval]:
        row = self._conn().execute(
            "SELECT * FROM approvals WHERE username=? AND fingerprint=?",
            (username, self._row_fp(pubkey)),
        ).fetchone()
        if row is None:
            return None
        approval = Approval.from_json(dict(row))
        return None if approval.is_expired() else approval

    def revoke(self, username: str, pubkey: str) -> bool:
        cur = self._conn().execute(
            "DELETE FROM approvals WHERE username=? AND fingerprint=?",
            (username, self._row_fp(pubkey)),
        )
        self._conn().commit()
        return cur.rowcount > 0

    def sweep(self, now: Optional[float] = None) -> int:
        now = now if now is not None else __import__("time").time()
        cur = self._conn().execute(
            "DELETE FROM approvals WHERE issued_at + ttl_seconds <= ?", (now,)
        )
        self._conn().commit()
        return cur.rowcount

    def list_for(self, username: str) -> list[Approval]:
        rows = self._conn().execute(
            "SELECT * FROM approvals WHERE username=?", (username,)
        ).fetchall()
        out = []
        for row in rows:
            approval = Approval.from_json(dict(row))
            if not approval.is_expired():
                out.append(approval)
        return out

    def list_since(self, since: float) -> list[Approval]:
        rows = self._conn().execute(
            "SELECT * FROM approvals WHERE issued_at >= ?", (since,)
        ).fetchall()
        return [Approval.from_json(dict(r)) for r in rows]

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @staticmethod
    def _row_fp(pubkey: str) -> str:
        # Imported lazily to avoid a cycle; base defines the canonicaliser.
        from .base import _key_fingerprint

        return _key_fingerprint(pubkey)
