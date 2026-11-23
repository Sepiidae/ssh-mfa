"""The ``AuthorizedKeysCommand`` role of the sshd plugin.

sshd invokes this for every public-key authentication attempt with the argv::

    mfa-sshd authorized-keys <username> <key-type> <base64-key> [comment]

Behaviour:

* If the shared store holds a **live** approval for exactly this
  ``(username, public key)``, print the offered key back to stdout in
  ``authorized_keys`` format. sshd treats that as a match and grants access —
  no key file on disk is needed.
* Otherwise print nothing to stdout (deny the key) and write, to **stderr**,
  the instruction the user should follow to authenticate: the ``mfa-ssh``
  command and the SAML login URL. sshd relays AuthorizedKeysCommand stderr to
  the connecting user, so this is how "the server responds with a url and/or a
  command".

The check is synchronous and network-free: it only reads the local store, so a
login handshake never blocks on the auth server. The store is kept fresh by the
:mod:`~mfa_sshd.watcher` daemon polling in the background.
"""

from __future__ import annotations

import sys
from typing import Optional

from .config import load_config, Config
from mfa_store.factory import open_store


def parse_akc_args(argv: list[str]) -> tuple[str, str, str, str]:
    """Parse sshd's ``authorized-keys`` argv into (username, keytype, b64, comment)."""

    # argv = ["authorized-keys", user, type, base64, (comment?)]
    if len(argv) < 4:
        raise ValueError(f"expected at least 4 args, got {argv}")
    username = argv[1]
    keytype = argv[2]
    b64 = argv[3]
    comment = argv[4] if len(argv) > 4 else ""
    if not username or not keytype or not b64:
        raise ValueError(f"empty field in args: {argv}")
    return username, keytype, b64, comment


def offered_key_line(keytype: str, b64: str, comment: str) -> str:
    line = f"{keytype} {b64}"
    if comment:
        line += f" {comment}"
    return line


def _instruction(config: Config, username: str, host: Optional[str]) -> str:
    base = config.auth_server.rstrip("/")
    host_frag = f"&host={host}" if host else ""
    url = f"{base}/?ssh_user={username}{host_frag}"
    host_arg = f" --host {host}" if host else ""
    return (
        "\n"
        "SSH MFA authentication required.\n"
        "Run this on your machine to authenticate, then re-run ssh:\n"
        f"    mfa-ssh {username}{host_arg}\n"
        f"or open:\n"
        f"    {url}\n"
    )


def run_authorized_keys(argv: list[str], config: Optional[Config] = None,
                        store=None, out=None, err=None) -> int:
    """Execute the AuthorizedKeysCommand logic. Returns the process exit code."""

    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    config = config or load_config()

    try:
        username, keytype, b64, comment = parse_akc_args(argv)
    except ValueError as exc:
        print(f"mfa-sshd: {exc}", file=err)
        return 1

    key_line = offered_key_line(keytype, b64, comment)

    if store is None:
        try:
            store = open_store(config.store)
        except Exception as exc:  # store misconfigured: fail open? No — deny safely.
            print(f"mfa-sshd: store unavailable: {exc}", file=err)
            print(_instruction(config, username, None), file=err)
            return 0  # deny key, but tell the user how to proceed

    from mfa_store.base import _key_fingerprint
    # Reconstruct the full key text the store was keyed on.
    pubkey_text = key_line
    approval = store.lookup(username, pubkey_text)

    if approval is not None:
        # Live approval: emit the offered key so sshd grants it.
        print(key_line, file=out)
        return 0

    # No live approval: deny the key and instruct the user.
    # Best-effort host from SSH_CONNECTION/SSH_CLIENT env if present.
    host = None
    for env in ("SSH_CLIENT", "SSH_CONNECTION"):
        val = __import__("os").environ.get(env, "")
        if val:
            host = val.split()[0]
            break
    print(_instruction(config, username, host), file=err)
    return 0  # exit 0 with empty stdout = "key not authorized" to sshd
