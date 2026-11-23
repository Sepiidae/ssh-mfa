"""``mfa_sshd`` — the SSH MFA sshd plugin.

Two roles, matching the spec ("creates the url, and monitors the server for
acceptable username|ssh public key matches"):

* :mod:`mfa_sshd.authorizedkeys` — the ``AuthorizedKeysCommand`` sshd invokes on
  every public-key attempt. It checks the shared store for a live
  ``(username, pubkey)`` approval and, if present, emits the key so sshd grants
  access. This is the synchronous "is this match acceptable?" check.

* :mod:`mfa_sshd.watcher` — a background daemon that *polls the auth server
  asynchronously* for newly-granted approvals and writes them into the local
  store, so the AuthorizedKeysCommand never has to touch the network during a
  login handshake. This is the "poll the server async" half.

The single entry point :func:`main` (``mfa-sshd``) dispatches to either role.
"""

from .config import load_config, Config
from .authorizedkeys import run_authorized_keys, parse_akc_args
from .watcher import Watcher
from .server import main

__all__ = [
    "load_config",
    "Config",
    "run_authorized_keys",
    "parse_akc_args",
    "Watcher",
    "main",
]
