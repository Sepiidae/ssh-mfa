"""Redis-backed store.

Best when approvals must be shared across many target hosts without a shared
filesystem: every host points at the same Redis. TTL is native to Redis, so
expiry is enforced server-side even if nobody calls :meth:`sweep`.

The optional ``prefix`` lets several deployments share one Redis namespace.
Requires ``redis`` (``pip install redis``).
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .base import Approval, Store, StoreError

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency
    redis = None


class RedisStore(Store):
    def __init__(self, host="localhost", port=6379, db=0,
                 prefix="ssh-mfa", ttl_default=86400, url=None, **kw):
        if redis is None:
            raise StoreError("redis backend requires 'pip install redis'")
        self.prefix = prefix
        self.ttl_default = ttl_default
        self._client = redis.Redis(
            host=host, port=port, db=db,
            **( {"from_url": url} if url else {} ),
            decode_responses=True,
            **kw,
        )
        # Fail fast if the server is unreachable, rather than at first grant.
        try:
            self._client.ping()
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"cannot reach redis: {exc}") from exc

    def _pk(self, username: str, fingerprint: str) -> str:
        return f"{self.prefix}:{username}:{fingerprint}"

    def _user_set(self, username: str) -> str:
        return f"{self.prefix}:user:{username}"

    def grant(self, approval: Approval) -> None:
        a = approval
        if a.ttl_seconds <= 0:
            a.ttl_seconds = self.ttl_default
        pk = self._pk(a.username, a.fingerprint)
        pipe = self._client.pipeline()
        pipe.set(pk, json.dumps(a.to_json()), ex=a.ttl_seconds)
        pipe.sadd(self._user_set(a.username), a.fingerprint)
        pipe.expire(self._user_set(a.username), a.ttl_seconds + 60)
        pipe.execute()

    def lookup(self, username: str, pubkey: str) -> Optional[Approval]:
        from .base import _key_fingerprint

        raw = self._client.get(self._pk(username, _key_fingerprint(pubkey)))
        if raw is None:
            return None
        approval = Approval.from_json(json.loads(raw))
        return None if approval.is_expired() else approval

    def revoke(self, username: str, pubkey: str) -> bool:
        from .base import _key_fingerprint

        fp = _key_fingerprint(pubkey)
        deleted = self._client.delete(self._pk(username, fp))
        self._client.srem(self._user_set(username), fp)
        return deleted > 0

    def sweep(self, now: Optional[float] = None) -> int:
        # Redis already expires keys; sweep is a no-op beyond returning 0.
        return 0

    def list_for(self, username: str) -> list[Approval]:
        fps = self._client.smembers(self._user_set(username))
        out = []
        for fp in fps:
            raw = self._client.get(f"{self.prefix}:{username}:{fp}")
            if raw is None:
                continue
            approval = Approval.from_json(json.loads(raw))
            if not approval.is_expired():
                out.append(approval)
        return out

    def list_since(self, since: float) -> list[Approval]:
        # Redis has no server-side scan-by-time; scan the keyspace and filter.
        out = []
        for key in self._client.scan_iter(match=f"{self.prefix}:*:*"):
            if ":user:" in key:
                continue
            raw = self._client.get(key)
            if raw is None:
                continue
            approval = Approval.from_json(json.loads(raw))
            if approval.issued_at >= since:
                out.append(approval)
        return out

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass
