"""Postgres-backed store.

For deployments that already run Postgres and want durable, queryable audit of
who was granted access, when, and from which auth server. A single shared
database means every target host and auth server reads the same approvals.

Requires ``psycopg`` (``pip install psycopg[binary]``).
"""

from __future__ import annotations

import time
from typing import Optional

from .base import Approval, Store, StoreError

try:
    import psycopg
except ImportError:  # pragma: no cover - optional dependency
    psycopg = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ssh_mfa_approvals (
    username    text    NOT NULL,
    fingerprint text    NOT NULL,
    pubkey      text    NOT NULL,
    identity    text    NOT NULL,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    ttl_seconds integer NOT NULL DEFAULT 86400,
    challenge   text    NOT NULL DEFAULT '',
    source      text    NOT NULL DEFAULT '',
    PRIMARY KEY (username, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_ssh_mfa_user ON ssh_mfa_approvals(username);
"""


class PostgresStore(Store):
    def __init__(self, dsn, ttl_default=86400, schema=True):
        if psycopg is None:
            raise StoreError("postgres backend requires 'pip install psycopg[binary]'")
        self.dsn = dsn
        self.ttl_default = ttl_default
        if schema:
            with psycopg.connect(self.dsn) as conn:
                conn.execute(_SCHEMA)

    def grant(self, approval: Approval) -> None:
        a = approval
        if a.ttl_seconds <= 0:
            a.ttl_seconds = self.ttl_default
        with psycopg.connect(self.dsn) as conn:
            conn.execute(
                """
                INSERT INTO ssh_mfa_approvals
                    (username, fingerprint, pubkey, identity, issued_at,
                     ttl_seconds, challenge, source)
                VALUES (%s,%s,%s,%s, now(), %s,%s,%s)
                ON CONFLICT (username, fingerprint) DO UPDATE SET
                    pubkey=excluded.pubkey,
                    identity=excluded.identity,
                    issued_at=now(),
                    ttl_seconds=excluded.ttl_seconds,
                    challenge=excluded.challenge,
                    source=excluded.source
                """,
                (a.username, a.fingerprint, a.pubkey, a.identity,
                 a.ttl_seconds, a.challenge, a.source),
            )

    def lookup(self, username: str, pubkey: str) -> Optional[Approval]:
        from .base import _key_fingerprint

        with psycopg.connect(self.dsn) as conn:
            row = conn.execute(
                """
                SELECT username, fingerprint, pubkey, identity,
                       EXTRACT(EPOCH FROM issued_at) AS issued_at,
                       ttl_seconds, challenge, source
                FROM ssh_mfa_approvals
                WHERE username=%s AND fingerprint=%s
                """,
                (username, _key_fingerprint(pubkey)),
            ).fetchone()
        if row is None:
            return None
        approval = Approval.from_json(dict(row))
        return None if approval.is_expired() else approval

    def revoke(self, username: str, pubkey: str) -> bool:
        from .base import _key_fingerprint

        with psycopg.connect(self.dsn) as conn:
            cur = conn.execute(
                "DELETE FROM ssh_mfa_approvals WHERE username=%s AND fingerprint=%s",
                (username, _key_fingerprint(pubkey)),
            )
            return cur.rowcount > 0

    def sweep(self, now: Optional[float] = None) -> int:
        now = now if now is not None else time.time()
        with psycopg.connect(self.dsn) as conn:
            cur = conn.execute(
                "DELETE FROM ssh_mfa_approvals "
                "WHERE to_timestamp(issued_at) + make_interval(secs=>ttl_seconds) <= now()",
            )
            return cur.rowcount

    def list_for(self, username: str) -> list[Approval]:
        with psycopg.connect(self.dsn) as conn:
            rows = conn.execute(
                """
                SELECT username, fingerprint, pubkey, identity,
                       EXTRACT(EPOCH FROM issued_at) AS issued_at,
                       ttl_seconds, challenge, source
                FROM ssh_mfa_approvals WHERE username=%s
                """,
                (username,),
            ).fetchall()
        out = []
        for row in rows:
            approval = Approval.from_json(dict(row))
            if not approval.is_expired():
                out.append(approval)
        return out

    def list_since(self, since: float) -> list[Approval]:
        with psycopg.connect(self.dsn) as conn:
            rows = conn.execute(
                """
                SELECT username, fingerprint, pubkey, identity,
                       EXTRACT(EPOCH FROM issued_at) AS issued_at,
                       ttl_seconds, challenge, source
                FROM ssh_mfa_approvals WHERE issued_at >= to_timestamp(%s)
                """,
                (since,),
            ).fetchall()
        return [Approval.from_json(dict(r)) for r in rows]
