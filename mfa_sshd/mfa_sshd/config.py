"""Configuration loading for the sshd plugin.

Config can come from a YAML file (default ``/etc/ssh-mfa/mfa.yaml``) or an
environment variable. Only the keys the plugin needs are read; the store and
auth-server sections are passed through to the store bridge and watcher.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

try:  # optional; falls back to a tiny parser if PyYAML is absent
    import yaml
except Exception:  # pragma: no cover
    yaml = None

DEFAULT_CONFIG_PATH = "/etc/ssh-mfa/mfa.yaml"


@dataclass
class Config:
    store: dict = field(default_factory=dict)
    auth_server: str = "https://auth.example.org/mfa"
    poll_interval: float = 15.0
    approval_ttl: int = 86400
    log_path: str = "/var/log/ssh-mfa/sshd.log"
    extra_ssh_principals: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        return cls(
            store=data.get("store", {}),
            auth_server=data.get("auth_server", cls.auth_server),
            poll_interval=float(data.get("poll_interval", cls.poll_interval)),
            approval_ttl=int(data.get("approval_ttl", cls.approval_ttl)),
            log_path=data.get("log_path", cls.log_path),
            extra_ssh_principals=list(data.get("extra_ssh_principals", [])),
        )


def _simple_yaml(text: str) -> dict:
    """Minimal YAML subset parser used only when PyYAML is unavailable."""

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


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("MFA_SSHD_CONFIG", DEFAULT_CONFIG_PATH)
    data: dict = {}
    if path and os.path.exists(path):
        text = open(path, encoding="utf-8").read()
        data = yaml.safe_load(text) if yaml else _simple_yaml(text)
        data = data or {}
    # Environment overrides (handy for the AuthorizedKeysCommand's limited env).
    if os.environ.get("MFA_AUTH_SERVER"):
        data["auth_server"] = os.environ["MFA_AUTH_SERVER"]
    return Config.from_dict(data)
