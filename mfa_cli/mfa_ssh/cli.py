"""Command-line interface for ``mfa-ssh``."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import webbrowser
from pathlib import Path

DEFAULT_AUTH_SERVER = "https://auth.example.org/mfa"


def _default_pubkey() -> str:
    """Return the user's public key, preferring id_ed25519."""

    for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        pub = Path.home() / ".ssh" / f"{name}.pub"
        if pub.exists():
            return pub.read_text().strip()
    # Fall back to whatever ssh-keygen reports as the default identity.
    return ""


def _read_pubkey(arg: str | None) -> str:
    if arg:
        p = Path(arg).expanduser()
        if not p.exists():
            raise SystemExit(f"public key file not found: {p}")
        return p.read_text().strip()
    pk = _default_pubkey()
    if not pk:
        raise SystemExit(
            "no SSH public key found; generate one with 'ssh-keygen -t ed25519' "
            "or pass --pubkey PATH")
    return pk


def _post(url: str, payload: dict, timeout: float = 20.0) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _get(url: str, timeout: float = 20.0) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def prepare(auth_server: str, username: str, pubkey: str) -> dict:
    return _post(
        f"{auth_server.rstrip('/')}/api/v1/challenges",
        {"username": username, "pubkey": pubkey})


def status(auth_server: str, cid: str) -> dict:
    return _get(f"{auth_server.rstrip('/')}/api/v1/challenges/{cid}")


def _open_or_print(url: str, headless: bool) -> None:
    if headless or not webbrowser.open(url):
        print(f"\nOpen this URL to authenticate:\n  {url}\n")


def run(args: argparse.Namespace) -> int:
    username = args.username or _ssh_whoami(args.host)
    pubkey = _read_pubkey(args.pubkey)
    print(f"Preparing MFA for {username} ...")

    try:
        prep = prepare(args.server, username, pubkey)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise SystemExit(f"auth server error ({exc.code}): {body}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach auth server {args.server}: {exc.reason}")

    if "error" in prep:
        raise SystemExit(f"auth server rejected request: {prep['error']}")

    cid = prep["challenge_id"]
    saml_url = prep.get("saml_url")
    print(f"Challenge {cid[:8]}… created. Fingerprint: {prep.get('fingerprint')}")

    if saml_url:
        _open_or_print(saml_url, headless=args.headless)
    else:
        print("No SAML URL returned by server; it may be unavailable.")

    print("Waiting for authentication (Ctrl-C to cancel)...")
    deadline = time.time() + args.timeout
    last = ""
    while time.time() < deadline:
        try:
            st = status(args.server, cid)
        except Exception:
            st = {"state": "pending"}
        state = st.get("state", "pending")
        if state != last:
            print(f"  state: {state}")
            last = state
        if state == "approved":
            print(f"\nSuccess: {st.get('identity')} approved for {username}.")
            print("Re-run your original 'ssh' command now; access is granted.")
            return 0
        if state in ("failed", "expired"):
            reason = st.get("error") or state
            raise SystemExit(f"Login {state}: {reason}")
        time.sleep(args.poll_interval)

    raise SystemExit("Timed out waiting for authentication.")


def _ssh_whoami(host: str | None) -> str:
    """Best-effort: ask ssh which user it would use for *host*."""

    import subprocess

    try:
        cmd = ["ssh", "-G"]
        if host:
            cmd.append(host)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            if line.startswith("user "):
                return line.split(" ", 1)[1].strip()
    except Exception:
        pass
    return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mfa-ssh",
        description="Authenticate for SSH MFA via SAML, then re-run your ssh command.")
    p.add_argument("username", nargs="?", help="target username (default: from ssh -G)")
    p.add_argument("--host", help="target host (used with ssh -G to resolve the user)")
    p.add_argument("--server", default=os.environ.get("MFA_AUTH_SERVER", DEFAULT_AUTH_SERVER),
                   help="auth server base URL")
    p.add_argument("--pubkey", help="path to SSH public key (default: ~/.ssh/id_ed25519.pub)")
    p.add_argument("--headless", action="store_true",
                   help="print the URL instead of opening a browser")
    p.add_argument("--timeout", type=float, default=300.0,
                   help="give up after N seconds (default: 300)")
    p.add_argument("--poll-interval", type=float, default=3.0,
                   help="seconds between status polls (default: 3)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
