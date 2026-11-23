"""Config loading for the auth server.

Shares the same YAML file as the sshd plugin (``store`` section), plus the
auth-server-only sections (``saml``, ``authz``, ``challenge_ttl``,
``approval_ttl``). Uses PyYAML when available, else a tiny built-in parser.
"""

from __future__ import annotations

import os
from typing import Any

try:
    import yaml
    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False

DEFAULT_CONFIG_PATH = "/etc/ssh-mfa/mfa.yaml"


def _coerce(val: str) -> Any:
    if val.startswith("[") and val.endswith("]"):
        return [_coerce(x) for x in val[1:-1].split(",") if x.strip()]
    low = val.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val.strip().strip('"').strip("'")


def _simple_yaml(text: str) -> dict:
    root: dict = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        key, _, val = line.strip().partition(":")
        val = val.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if val == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _coerce(val)
    return root


def load_config(path: str | None = None) -> dict:
    path = path or os.environ.get("MFA_AUTH_CONFIG", DEFAULT_CONFIG_PATH)
    data: dict = {}
    if path and os.path.exists(path):
        text = open(path, encoding="utf-8").read()
        data = yaml.safe_load(text) if _HAVE_YAML else _simple_yaml(text)
        data = data or {}
    # Ensure the SAML block exists.
    data.setdefault("saml", {})
    data["saml"].setdefault("enabled", True)
    data.setdefault("store", {"backend": "sqlite",
                              "path": "/var/lib/ssh-mfa/approvals.db"})
    data.setdefault("challenge_ttl", 300)
    data.setdefault("approval_ttl", 86400)
    return data
