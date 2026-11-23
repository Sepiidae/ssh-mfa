"""``mfa-ssh`` — the user-facing CLI that drives an SSH MFA login.

The user runs it after sshd tells them to. It:

  1. reads the user's SSH public key (default ``~/.ssh/id_ed25519.pub``),
  2. asks the auth server to *prepare* a challenge bound to (username, pubkey),
  3. opens the SAML login URL (or prints it for a locked-down terminal),
  4. polls the challenge until it is approved, failed, or expired,
  5. reports success so the user can re-run ``ssh``.

It depends only on the Python standard library so it can run on any bastion or
laptop without installing Flask/SAML packages.
"""

from .cli import main

__all__ = ["main"]
