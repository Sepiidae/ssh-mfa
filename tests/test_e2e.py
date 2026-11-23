"""End-to-end test of the SSH MFA flow, without a live IdP.

Simulates the whole pipeline against a temp SQLite store:

  1. CLI-equivalent: prepare a challenge (binds username + pubkey).
  2. SAML ACS-equivalent: an authorized identity satisfies the challenge,
     and the approval is written to the shared store.
  3. sshd-equivalent: the AuthorizedKeysCommand is invoked with the offered key
     and must emit it (grant) once approved, and deny + instruct before.
  4. Expiry: after the TTL elapses, the key is no longer emitted.
  5. Watcher: /api/v1/approvals replicates the grant to a second store.
"""

import io
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mfa_store"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mfa_auth"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mfa_sshd"))

from mfa_auth.app import create_app
from mfa_store.factory import open_store
from mfa_store.base import Approval
from mfa_sshd.authorizedkeys import run_authorized_keys
from mfa_sshd.config import Config

PUBKEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkLzrm0SdG7UOxq4NNatGDXq"
          "R3En11bGQaV1Z alice@laptop")
USERNAME = "alice"


def make_config(store_path, auth_ttl=3600):
    return {
        "store": {"backend": "sqlite", "path": store_path},
        "auth_server": "https://auth.example.org/mfa",
        "approval_ttl": auth_ttl,
    }


def test_flow():
    d = tempfile.mkdtemp()
    store_path = os.path.join(d, "approvals.db")
    config = make_config(store_path, auth_ttl=2)  # 2s TTL so we can test expiry

    app = create_app(config)
    client = app.test_client()

    # 1. Prepare a challenge (what mfa-ssh does).
    resp = client.post("/api/v1/challenges", json={
        "username": USERNAME, "pubkey": PUBKEY})
    assert resp.status_code == 200, resp.data
    prep = resp.get_json()
    cid = prep["challenge_id"]
    print(f"[1] challenge prepared: {cid[:8]}…  fp={prep['fingerprint'][:20]}…")

    # Before approval: AuthorizedKeysCommand must deny and instruct.
    out, err = io.StringIO(), io.StringIO()
    code = run_authorized_keys(
        ["authorized-keys", USERNAME, "ssh-ed25519",
         "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkLzrm0SdG7UOxq4NNatGDXqR3En11bGQaV1Z",
         "alice@laptop"],
        config=Config.from_dict(config), out=out, err=err)
    assert out.getvalue().strip() == "", f"should deny before approval, got: {out.getvalue()!r}"
    assert "mfa-ssh" in err.getvalue() and "auth.example.org" in err.getvalue()
    print("[2] before approval: key denied, instruction printed to user OK")

    # 2. SAML ACS success for an authorized identity (alice@example.org).
    store = open_store(config["store"])
    from mfa_auth.challenge import State
    ch = app.extensions["mfa"]["challenges"].get(cid)
    from mfa_auth.store_bridge import write_approval
    write_approval(store, ch, "alice@example.org", ttl_seconds=2, source="test")
    app.extensions["mfa"]["challenges"].transition(cid, State.APPROVED,
                                                   identity="alice@example.org")
    store.close()
    print("[3] SAML success recorded; approval written to store")

    # 3. After approval: AuthorizedKeysCommand must emit the key.
    out, err = io.StringIO(), io.StringIO()
    code = run_authorized_keys(
        ["authorized-keys", USERNAME, "ssh-ed25519",
         "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkLzrm0SdG7UOxq4NNatGDXqR3En11bGQaV1Z",
         "alice@laptop"],
        config=Config.from_dict(config), out=out, err=err)
    emitted = out.getvalue().strip()
    assert emitted == PUBKEY, f"expected the key emitted, got: {emitted!r}"
    print(f"[4] after approval: key emitted -> {emitted.split()[2]} OK")

    # 4. Expiry: wait out the TTL, then the key must no longer be emitted.
    time.sleep(2.3)
    out, err = io.StringIO(), io.StringIO()
    run_authorized_keys(
        ["authorized-keys", USERNAME, "ssh-ed25519",
         "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkLzrm0SdG7UOxq4NNatGDXqR3En11bGQaV1Z",
         "alice@laptop"],
        config=Config.from_dict(config), out=out, err=err)
    assert out.getvalue().strip() == "", "expired approval must not emit the key"
    print("[5] after TTL: key denied again (expiry enforced) OK")

    # 5. Watcher replication: /api/v1/approvals into a fresh store.
    store2 = open_store({"backend": "sqlite", "path": os.path.join(d, "replica.db")})
    # Re-grant a fresh (non-expired) approval so the watcher has something to copy.
    store_fresh = open_store(config["store"])
    ch2 = app.extensions["mfa"]["challenges"].get(cid)
    # (cid already expired; create a fresh challenge for the replication test)
    store_fresh.close()
    resp2 = client.post("/api/v1/challenges", json={"username": USERNAME, "pubkey": PUBKEY})
    cid2 = resp2.get_json()["challenge_id"]
    store_fresh = open_store(config["store"])
    ch2 = app.extensions["mfa"]["challenges"].get(cid2)
    write_approval(store_fresh, ch2, "alice@example.org", ttl_seconds=3600, source="test")
    store_fresh.close()
    # Hit the approvals endpoint and replicate everything into store2.
    ar = client.get("/api/v1/approvals?since=0")
    payload = ar.get_json()
    for row in payload["approvals"]:
        store2.grant(Approval.from_json(row))
    got = store2.lookup(USERNAME, PUBKEY)
    store2.close()
    assert got is not None, "watcher replication should copy the approval"
    print(f"[6] watcher replication: approval present on replica host OK "
          f"(identity={got.identity})")

    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    test_flow()
