"""Abstract interface and data model shared by every store backend."""

from __future__ import annotations

import abc
import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional


class StoreError(Exception):
    """Raised for configuration and backend-level failures."""


def _key_fingerprint(pubkey: str) -> str:
    """Return the SSH-style SHA256 fingerprint of *pubkey*.

    Normalising to a fingerprint (rather than the raw blob) keeps the store
    key stable regardless of trailing comments or whitespace, and is what
    sshd ultimately compares against.
    """

    parts = pubkey.split()
    if len(parts) >= 2:
        try:
            raw = base64.b64decode(parts[1] + "==")
        except Exception:
            raw = None
        if raw:
            digest = hashlib.sha256(raw).digest()
            return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    # Not a recognisable/valid key: fall back to a hash of the literal string so
    # we still get a stable, collision-resistant key rather than crashing.
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(pubkey.encode()).digest()
    ).decode("ascii").rstrip("=")


@dataclass
class Approval:
    """A single granted approval: *identity* may use *pubkey* as *username*."""

    username: str
    pubkey: str
    identity: str
    issued_at: float = field(default_factory=time.time)
    ttl_seconds: int = 86400
    challenge: str = ""
    source: str = ""  # which auth server host recorded it

    @property
    def fingerprint(self) -> str:
        return _key_fingerprint(self.pubkey)

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.ttl_seconds

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at

    def to_json(self) -> dict:
        return {
            "username": self.username,
            "pubkey": self.pubkey,
            "identity": self.identity,
            "issued_at": self.issued_at,
            "ttl_seconds": self.ttl_seconds,
            "challenge": self.challenge,
            "source": self.source,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Approval":
        return cls(
            username=data["username"],
            pubkey=data["pubkey"],
            identity=data["identity"],
            issued_at=float(data.get("issued_at", time.time())),
            ttl_seconds=int(data.get("ttl_seconds", 86400)),
            challenge=data.get("challenge", ""),
            source=data.get("source", ""),
        )


class Store(abc.ABC):
    """Backend-agnostic approval store.

    Implementations must be safe for concurrent readers (the AuthorizedKeysCommand
    runs many times in parallel under sshd) and must treat expiry as authoritative:
    an expired approval behaves exactly as if it were absent.
    """

    @abc.abstractmethod
    def grant(self, approval: Approval) -> None:
        """Record *approval*, replacing any existing one for the same pair."""

    @abc.abstractmethod
    def lookup(self, username: str, pubkey: str) -> Optional[Approval]:
        """Return the live approval for (username, pubkey) or ``None``.

        Must return ``None`` for expired or missing entries.
        """

    @abc.abstractmethod
    def revoke(self, username: str, pubkey: str) -> bool:
        """Delete the approval for the pair; return True if something was removed."""

    @abc.abstractmethod
    def sweep(self, now: Optional[float] = None) -> int:
        """Permanently delete expired rows; return the count removed."""

    @abc.abstractmethod
    def list_for(self, username: str) -> list[Approval]:
        """All live approvals for *username* (used by the CLI to show status)."""

    @abc.abstractmethod
    def list_since(self, since: float) -> list[Approval]:
        """All approvals whose ``issued_at`` is >= *since* (live or expired).

        Used by the auth server's ``/api/v1/approvals`` endpoint so the watcher
        on each target host can replicate them into its local store.
        """

    def close(self) -> None:  # pragma: no cover - default no-op
        """Release backend resources if needed."""

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
