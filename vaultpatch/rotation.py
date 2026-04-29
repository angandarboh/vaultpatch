"""Secret rotation logic for vaultpatch."""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from typing import List, Optional

import hvac

from .config import NamespaceConfig

_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


def generate_secret(length: int = 32) -> str:
    """Return a cryptographically random secret string of *length* characters."""
    if length < 8:
        raise ValueError("Secret length must be at least 8 characters.")
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


@dataclass
class RotationResult:
    namespace: str
    path: str
    new_value: Optional[str] = None
    error: Optional[str] = None


@dataclass
class RotationReport:
    results: List[RotationResult] = field(default_factory=list)

    def failed(self) -> List[RotationResult]:
        """Return results where an error occurred."""
        return [r for r in self.results if r.error]

    def successes(self) -> List[RotationResult]:
        """Return results that completed without error."""
        return [r for r in self.results if not r.error]

    def summary(self) -> str:
        ok = len(self.successes())
        fail = len(self.failed())
        return f"{ok} rotated successfully, {fail} failed."

    def paths_rotated(self) -> List[str]:
        """Return paths of successfully rotated secrets."""
        return [r.path for r in self.successes()]


def rotate_secret(
    client: hvac.Client,
    ns: NamespaceConfig,
    path: str,
    key: str = "value",
    length: int = 32,
) -> RotationResult:
    """Generate a new secret and write it to *path* in Vault.

    Returns a :class:`RotationResult` describing the outcome.
    """
    new_value = generate_secret(length)
    try:
        mount, secret_path = _split_mount(path)
        client.secrets.kv.v2.create_or_update_secret(
            path=secret_path,
            secret={key: new_value},
            mount_point=mount,
        )
        return RotationResult(namespace=ns.name, path=path, new_value=new_value)
    except Exception as exc:  # noqa: BLE001
        return RotationResult(namespace=ns.name, path=path, error=str(exc))


def _split_mount(path: str) -> tuple[str, str]:
    """Split 'mount/some/path' into ('mount', 'some/path')."""
    parts = path.lstrip("/").split("/", 1)
    if len(parts) < 2:
        raise ValueError(f"Path '{path}' must include a mount point prefix.")
    return parts[0], parts[1]
