"""``mfa-sshd`` entry point.

Dispatches the sshd plugin's roles:

    mfa-sshd authorized-keys <user> <type> <b64> [comment]   # AuthorizedKeysCommand
    mfa-sshd watch              # background poller daemon
    mfa-sshd sweep              # purge expired approvals from the store
    mfa-sshd status <username>  # show a user's live approvals
"""

from __future__ import annotations

import argparse
import sys
import time

from .config import load_config
from .authorizedkeys import run_authorized_keys
from .watcher import Watcher


def _cmd_sweep(config) -> int:
    from mfa_store.factory import open_store
    store = open_store(config.store)
    try:
        removed = store.sweep()
    finally:
        store.close()
    print(f"removed {removed} expired approval(s)")
    return 0


def _cmd_status(config, username: str) -> int:
    from mfa_store.factory import open_store
    store = open_store(config.store)
    try:
        approvals = store.list_for(username)
    finally:
        store.close()
    if not approvals:
        print(f"{username}: no live approvals")
        return 0
    for a in approvals:
        remaining = int(a.expires_at - time.time())
        print(f"{username}: {a.identity} {a.fingerprint[:24]}… expires in {remaining}s")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="mfa-sshd")
    sub = parser.add_subparsers(dest="role", required=True)

    ak = sub.add_parser("authorized-keys",
                        help="sshd AuthorizedKeysCommand handler")
    ak.add_argument("username")
    ak.add_argument("keytype")
    ak.add_argument("b64")
    ak.add_argument("comment", nargs="?", default="")

    sub.add_parser("watch", help="run the background poller daemon")
    sub.add_parser("sweep", help="remove expired approvals")

    st = sub.add_parser("status", help="show a user's live approvals")
    st.add_argument("username")

    args = parser.parse_args(argv)
    config = load_config()

    if args.role == "authorized-keys":
        return run_authorized_keys(
            ["authorized-keys", args.username, args.keytype, args.b64, args.comment],
            config=config)
    if args.role == "watch":
        Watcher(config).run_forever()
        return 0
    if args.role == "sweep":
        return _cmd_sweep(config)
    if args.role == "status":
        return _cmd_status(config, args.username)
    parser.error("unknown role")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
