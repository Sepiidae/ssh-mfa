"""Pluggable shared store for SSH MFA approvals.

The store is the single source of truth shared between the auth server
(which writes approvals) and the target host (whose sshd AuthorizedKeysCommand
reads them). It records, per (username, ssh_public_key):

  * the authenticated identity from the IdP
  * when the approval was granted (issued_at)
  * how long it is valid for (ttl_seconds)
  * the challenge it satisfied (for audit / de-duplication)

Three backends implement the same interface:

  * :class:`SqliteStore`   - zero extra infrastructure, a local file
  * :class:`RedisStore`    - fast, native TTL, multi-host
  * :class:`PostgresStore` - durable, queryable, shared audit log

Select one with :func:`open_store` from a config dict, e.g.::

    {"backend": "sqlite", "path": "/var/lib/ssh-mfa/approvals.db"}
    {"backend": "redis",  "host": "redis.internal", "db": 3}
    {"backend": "postgres","dsn": "postgresql://..."}
"""

from .base import Store, Approval, StoreError
from .factory import open_store, store_from_env, BACKENDS

__all__ = [
    "Store",
    "Approval",
    "StoreError",
    "open_store",
    "store_from_env",
    "BACKENDS",
]
