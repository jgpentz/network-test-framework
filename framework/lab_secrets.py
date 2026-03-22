"""Load lab credentials from a YAML file (not committed — see config/secrets.example.yaml)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class LabSecrets:
    """SSH credentials for the lab switch (and similar Netmiko targets)."""

    username: str
    password: str
    enable_secret: str | None = None


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_secrets_path() -> Path:
    env = os.environ.get("NETWORK_TEST_SECRETS_FILE")
    if env:
        return Path(env)
    return project_root() / "config" / "secrets.yaml"


def load_lab_secrets(path: Path | None = None) -> LabSecrets:
    """Load username/password from YAML.

    Set ``NETWORK_TEST_SECRETS_FILE`` to override the default path.
    """
    p = path or default_secrets_path()
    if not p.is_file():
        raise FileNotFoundError(
            f"Secrets file not found: {p}. Copy config/secrets.example.yaml to config/secrets.yaml."
        )
    with open(p, encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}
    try:
        username = str(data["username"])
        password = str(data["password"])
    except KeyError as exc:
        raise KeyError(
            "secrets file must contain top-level 'username' and 'password' keys"
        ) from exc
    enable = data.get("enable_secret")
    return LabSecrets(
        username=username,
        password=password,
        enable_secret=str(enable) if enable is not None else None,
    )
