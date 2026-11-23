"""Backend selection for :mod:`mfa_store`.

A store is chosen from a small config dict (or environment variable). The same
config is read by the auth server (writer) and the target host (reader), so
they always agree on the backend and connection.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from .base import Store, StoreError

BACKENDS: dict[str, str] = {
    "sqlite": "mfa_store.sqlite_store:SqliteStore",
    "redis": "mfa_store.redis_store:RedisStore",
    "postgres": "mfa_store.postgres_store:PostgresStore",
}


def open_store(config: Mapping[str, Any]) -> Store:
    """Open the store described by *config*.

    ``config`` is ``{"backend": "sqlite", ...}`` plus backend-specific keys
    (``path`` for sqlite; ``host``/``port``/``db``/``url``/``prefix`` for redis;
    ``dsn`` for postgres). Raises :class:`StoreError` on unknown/missing backend.
    """

    if not config:
        raise StoreError("no store configuration provided")
    backend = str(config.get("backend") or "").lower()
    if backend not in BACKENDS:
        raise StoreError(
            f"unknown store backend {backend!r}; expected one of {sorted(BACKENDS)}"
        )
    module_name, class_name = BACKENDS[backend].split(":")
    module = __import__(module_name, fromlist=[class_name])
    cls = getattr(module, class_name)
    kwargs = {k: v for k, v in config.items() if k != "backend"}
    return cls(**kwargs)


def store_from_env(var: str = "MFA_STORE_CONFIG") -> Store:
    """Open the store named by a JSON config in environment variable *var*.

    Lets the sshd AuthorizedKeysCommand pick a backend with no code change, e.g.
    ``MFA_STORE_CONFIG='{"backend":"redis","host":"redis.internal","db":3}'``.
    """

    raw = os.environ.get(var)
    if not raw:
        raise StoreError(f"environment variable {var} is not set")
    import json

    return open_store(json.loads(raw))
