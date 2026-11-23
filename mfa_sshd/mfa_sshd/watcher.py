"""Background watcher: polls the auth server asynchronously.

The ``AuthorizedKeysCommand`` must be fast and network-free, so it cannot itself
wait for a SAML login to complete. Instead this daemon runs continuously on the
target host, polls the auth server for approvals that are new since the last
poll, and writes them into the local store. The AuthorizedKeysCommand then reads
that local store during the handshake.

This is the "monitor the server for acceptable username|ssh public key matches"
half of the plugin, running as a system service.
"""

from __future__ import annotations

import json
import signal
import sys
import time
import urllib.request
import urllib.error

from .config import load_config, Config
from mfa_store.factory import open_store


class Watcher:
    def __init__(self, config: Config, store=None, log=None):
        self.config = config
        self.store = store if store is not None else open_store(config.store)
        self.log = log
        self._last = 0.0
        self._stop = False

    def _log(self, msg: str) -> None:
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}\n"
        if self.log is not None:
            self.log.write(line)
            self.log.flush()
        else:
            sys.stderr.write(line)

    def poll_once(self) -> int:
        """Fetch new approvals since :attr:`_last` and write them locally."""

        base = self.config.auth_server.rstrip("/")
        url = f"{base}/api/v1/approvals?since={self._last}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            self._log(f"poll HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}")
            return 0
        except Exception as exc:  # noqa: BLE001
            self._log(f"poll failed: {exc}")
            return 0

        rows = payload.get("approvals", [])
        written = 0
        from mfa_store.base import Approval
        for row in rows:
            a = Approval.from_json(row)
            if a.is_expired():
                continue
            self.store.grant(a)
            written += 1
            self._log(f"granted {a.identity} -> {a.username} ({a.fingerprint[:20]}…) "
                      f"ttl={a.ttl_seconds}s")
        if rows:
            self._last = max(self._last, payload.get("server_time", time.time()))
        return written

    def run_forever(self) -> None:
        self._log(f"watcher started; polling {self.config.auth_server} "
                  f"every {self.config.poll_interval}s")

        def _handle(signum, frame):
            self._log(f"received signal {signum}; stopping")
            self._stop = True

        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
        while not self._stop:
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001
                self._log(f"unexpected error: {exc}")
            # sleep but stay responsive to signals
            slept = 0.0
            while slept < self.config.poll_interval and not self._stop:
                time.sleep(min(1.0, self.config.poll_interval - slept))
                slept += 1.0
        self.store.close()
        self._log("watcher stopped")
