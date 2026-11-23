"""In-memory challenge registry.

A *challenge* is a one-time, short-lived token that binds a target
``username`` to a specific SSH public key. The user authenticates via SAML;
when the assertion returns, the SP looks up the challenge by ``RelayState`` and
marks it approved. The pubkey is captured at prepare time, so no browser form is
needed — but the CLI can also hand the challenge to a browser for a human who
prefers to paste the key manually (see :mod:`mfa_auth.pages`).

Challenges are intentionally in-memory: they are transient login attempts, not
durable records. Durability lives in the shared approval store.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ChallengeError(Exception):
    pass


class State(str, Enum):
    PENDING = "pending"          # waiting for the user to authenticate
    AUTHENTICATED = "authenticated"  # SAML succeeded, awaiting approval
    APPROVED = "approved"        # approval written to the shared store
    FAILED = "failed"            # authentication rejected / errored
    EXPIRED = "expired"


@dataclass
class Challenge:
    id: str
    username: str
    pubkey: str
    fingerprint: str
    state: State = State.PENDING
    identity: str = ""           # IdP subject after successful SAML
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300)
    error: str = ""

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return now >= self.expires_at

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "fingerprint": self.fingerprint,
            "state": self.state.value,
            "identity": self.identity,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "error": self.error,
        }


class ChallengeStore:
    """Thread-safe registry of live challenges."""

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._items: dict[str, Challenge] = {}
        self._lock = threading.RLock()

    def create(self, username: str, pubkey: str, fingerprint: str) -> Challenge:
        with self._lock:
            self._sweep()
            cid = secrets.token_hex(16)
            now = time.time()
            c = Challenge(
                id=cid, username=username, pubkey=pubkey, fingerprint=fingerprint,
                created_at=now, expires_at=now + self._ttl,
            )
            self._items[cid] = c
            return c

    def get(self, cid: str) -> Optional[Challenge]:
        with self._lock:
            c = self._items.get(cid)
            if c is None:
                return None
            if c.is_expired():
                c.state = State.EXPIRED
                return c
            return c

    def transition(self, cid: str, state: State, **fields) -> Optional[Challenge]:
        with self._lock:
            c = self._items.get(cid)
            if c is None or c.is_expired():
                return None
            c.state = state
            for k, v in fields.items():
                setattr(c, k, v)
            return c

    def find_by_identity(self, identity: str) -> list[Challenge]:
        with self._lock:
            return [c for c in self._items.values()
                    if c.identity == identity and not c.is_expired()]

    def _sweep(self) -> None:
        expired = [cid for cid, c in self._items.items() if c.is_expired()]
        for cid in expired:
            self._items[cid].state = State.EXPIRED
        # drop expired after a grace period so status polling still sees them
        now = time.time()
        dead = [cid for cid, c in self._items.items()
                if c.is_expired() and now - c.expires_at > 600]
        for cid in dead:
            del self._items[cid]
