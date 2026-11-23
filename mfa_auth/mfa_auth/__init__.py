"""SSH MFA authentication server.

This is the "authentication machine" in the architecture: it is the SAML
Service Provider that redirects the user to a SAML 2.0 Identity Provider, validates the
returned assertion, and — on success — records an approval in the shared store
so the target host's sshd can grant access.

It exposes two surfaces:

* an HTTP API the CLI uses to *prepare* a login (mint a challenge bound to a
  username + public key, and get back the SAML URL to open), and to *poll* a
  challenge's status;
* the SAML endpoints (initiate / ACS) the browser follows during login.

The pubkey is bound to the challenge at prepare time, so by the time SAML
succeeds the server already knows exactly which key to approve — the user never
has to paste their key into a browser form.
"""

from .app import create_app
from .challenge import ChallengeStore, Challenge, ChallengeError
from .sp import SamlSP, SamlError

__all__ = [
    "create_app",
    "ChallengeStore",
    "Challenge",
    "ChallengeError",
    "SamlSP",
    "SamlError",
]
