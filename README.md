# SSH MFA (SAML 2.0)

Server-oriented multi-factor authentication for SSH. Users authenticate via
**SAML 2.0** against a configurable Identity Provider; on success, the target
server grants SSH access for a **time-limited** window by adding the user's
public key to the effective `authorized_keys` — no permanent key on disk, no
password on the box.

## The three parts

| Part | Package | Entry point | Role |
|------|---------|-------------|------|
| **1. sshd plugin** | `mfa_sshd/` | `mfa-sshd` | Runs on each **target** host. Two roles: the `AuthorizedKeysCommand` sshd invokes on every pubkey attempt (checks the local store for a live `username|pubkey` match and emits the key, or prints the auth command/URL to the user), and a background **watcher** that polls the auth server asynchronously and replicates approvals into the local store. |
| **2. auth server** | `mfa_auth/` | `mfa-auth` | Runs **once** (e.g. on `auth.example.org`). The SAML Service Provider: prepares challenges, drives the SAML redirect, validates the IdP assertion, and writes approvals to the shared store. |
| **3. CLI** | `mfa_cli/` | `mfa-ssh` | Runs on the **user's** machine. Reads the user's pubkey, asks the auth server to prepare a challenge, opens the SAML URL, polls until approved, then tells the user to re-run `ssh`. |
| shared store | `mfa_store/` | — | Pluggable backend (SQLite / Redis / Postgres) holding pending approvals and grants. |

## How a login flows

```
user$ ssh alice@target
  → sshd: no static key / key not authorised
  → AuthorizedKeysCommand (mfa-sshd): store has no live (alice, key) match
  → plugin prints to the user:
        Run:  mfa-ssh alice --host target
        or:   https://auth.example.org/mfa/?ssh_user=alice&host=target

user$ mfa-ssh alice --host target
  → POST /api/v1/challenges  (binds alice + pubkey)  → challenge id + SAML URL
  → opens SAML URL → user authenticates at the IdP
  → ACS validates assertion; identity alice@example.org matches → writes approval
  → polls until "approved" → "re-run your ssh"

user$ ssh alice@target
  → AuthorizedKeysCommand: watcher has replicated the approval into the local store
  → live (alice, key) match → emits key → sshd grants access
  → after approval_ttl the match expires → next login needs MFA again
```

The `AuthorizedKeysCommand` itself **never touches the network** — it only reads
the local store — so a login handshake can't hang on the auth server. The
watcher daemon keeps the local store fresh in the background ("poll the server
async").

## Key expiry

`approval_ttl` (in `mfa.yaml`) controls how long a grant lasts
(`86400` = 1 day, `604800` = 1 week, `2592000` = 30 days). Expiry is enforced
two ways: the store's `lookup` returns nothing once expired, and `mfa-sshd
sweep` permanently purges expired rows.

## Security model

- The pubkey is **bound to the challenge at prepare time**; SAML success alone
  is not enough — the IdP subject must match the challenge's username (or an
  `authz.allow_identities` allowlist).
- The IdP's signing certificate is **pinned** (`mfa_auth/sp.py`) from the IdP's
  published metadata; assertion signature, audience, and validity are verified.
- Approvals are short-lived; there is no long-term secret written to the target.
- The store is the single trust boundary shared between auth server and targets.

## Install

Each package is a standard `pyproject` project:

```bash
# on target hosts:
pip install ./mfa_store ./mfa_sshd
# on the auth host:
pip install ./mfa_store ./mfa_auth        # needs flask + python-saml
# on user machines:
pip install ./mfa_cli
```

## Configure

Copy `config/mfa.yaml` to `/etc/ssh-mfa/mfa.yaml` on every host and pick a
`store` backend. On target hosts, drop `config/sshd.d/60-mfa.conf` into
`/etc/ssh/sshd_config.d/` and `sshd -t` to validate, then `systemctl reload sshd`.
Enable the units:

```bash
# target host
sudo systemctl enable --now ssh-mfa-watcher
# auth host
sudo systemctl enable --now ssh-mfa-auth
```

## Test

```bash
PYTHONPATH=mfa_store:mfa_auth:mfa_sshd:mfa_cli python3 tests/test_e2e.py
```

Runs the whole pipeline against a temp SQLite store (no live IdP): prepare →
deny → SAML success → grant → expiry → watcher replication.
