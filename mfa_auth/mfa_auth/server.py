"""``mfa-auth`` — run the SSH MFA authentication server.

Usage::

    mfa-auth [--config /etc/ssh-mfa/mfa.yaml] [--host 0.0.0.0] [--port 443]

Reads the same config file as the sshd plugin (the ``store`` and ``saml``
sections). Requires Flask and python-saml to be installed.
"""

from __future__ import annotations

import argparse
import os

from .app import create_app
from .config_loader import load_config


def main(argv: list[str] | None = None) -> int:
    import sys

    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="mfa-auth")
    parser.add_argument("--config", default=os.environ.get("MFA_AUTH_CONFIG",
                                                           "/etc/ssh-mfa/mfa.yaml"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args(argv)

    config = load_config(args.config)
    app = create_app(config)
    app.logger.info("SSH MFA auth server listening on %s:%s", args.host, args.port)
    # In production, serve behind a TLS-terminating reverse proxy (nginx); the
    # SAML ACS requires https. debug is off by default.
    app.run(host=args.host, port=args.port,
            ssl_context=None,
            debug=bool(config.get("debug", False)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
