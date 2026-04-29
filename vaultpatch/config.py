"""Configuration loader for vaultpatch.

Loads and validates YAML config files that define Vault namespaces,
authentication settings, and secret paths to rotate.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass
class NamespaceConfig:
    name: str
    address: str
    token_env: str
    secret_paths: List[str] = field(default_factory=list)
    auth_method: str = "token"


@dataclass
class VaultPatchConfig:
    namespaces: List[NamespaceConfig] = field(default_factory=list)
    dry_run: bool = False
    audit_log: Optional[str] = None


class ConfigError(Exception):
    """Raised when the configuration file is invalid."""


def load_config(path: str | Path) -> VaultPatchConfig:
    """Load and validate a vaultpatch YAML configuration file.

    Args:
        path: Path to the YAML config file.

    Returns:
        A validated VaultPatchConfig instance.

    Raises:
        ConfigError: If required fields are missing or the file cannot be read.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    with config_path.open("r") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ConfigError("Config file must be a YAML mapping at the top level.")

    namespaces_raw = raw.get("namespaces")
    if not namespaces_raw or not isinstance(namespaces_raw, list):
        raise ConfigError("Config must define at least one namespace under 'namespaces'.")

    namespaces: List[NamespaceConfig] = []
    for idx, ns in enumerate(namespaces_raw):
        for required in ("name", "address", "token_env"):
            if required not in ns:
                raise ConfigError(
                    f"Namespace at index {idx} is missing required field '{required}'."
                )
        namespaces.append(
            NamespaceConfig(
                name=ns["name"],
                address=ns["address"],
                token_env=ns["token_env"],
                secret_paths=ns.get("secret_paths", []),
                auth_method=ns.get("auth_method", "token"),
            )
        )

    return VaultPatchConfig(
        namespaces=namespaces,
        dry_run=bool(raw.get("dry_run", False)),
        audit_log=raw.get("audit_log"),
    )
