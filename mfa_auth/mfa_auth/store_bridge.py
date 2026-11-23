"""Bridge between the auth server and the shared approval store.

The auth server is the *writer*; the target host's sshd AuthorizedKeysCommand
is the *reader*. This module centralises how a satisfied challenge becomes an
approval record, and how the CLI/ops tooling reads them back.
"""

from __future__ import annotations

from typing import Optional

from mfa_store.factory import open_store, store_from_env

from .challenge import Challenge


def get_store(config: dict):
    """Resolve the shared store from application config."""

    store_cfg = config.get("store")
    if not store_cfg:
        # Fall back to the environment so ops can point writer/reader at the
        # same backend without editing config files on every host.
        return store_from_env()
    return open_store(store_cfg)


def write_approval(store, challenge: Challenge, identity: str,
                   ttl_seconds: int, source: str = "") -> None:
    """Record that *identity* may use *challenge*'s pubkey as *challenge*'s user."""

    from mfa_store.base import Approval

    store.grant(Approval(
        username=challenge.username,
        pubkey=challenge.pubkey,
        identity=identity,
        issued_at=challenge.created_at,  # credit the approval from prepare time
        ttl_seconds=ttl_seconds,
        challenge=challenge.id,
        source=source,
    ))


def list_approvals(username: str) -> list:
    store = store_from_env()
    try:
        return store.list_for(username)
    finally:
        store.close()


def revoke_approval(username: str, fingerprint: str) -> bool:
    store = store_from_env()
    try:
        return store.revoke(username, fingerprint)
    finally:
        store.close()
