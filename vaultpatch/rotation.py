"""Secret rotation logic for vaultpatch."""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import hvac

from vaultpatch.config import NamespaceConfig


_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


def generate_secret(length: int = 32) -> str:
    """Generate a cryptographically secure random secret."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


@dataclass
class RotationResult:
    namespace: str
    path: str
    key: str
    success: bool
    rotated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None

    @property
    def failed(self) -> bool:
        return not self.success


@dataclass
class RotationReport:
    results: list[RotationResult] = field(default_factory=list)

    def successes(self) -> list[RotationResult]:
        return [r for r in self.results if r.success]

    def failures(self) -> list[RotationResult]:
        return [r for r in self.results if r.failed]

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.results),
            "succeeded": len(self.successes()),
            "failed": len(self.failures()),
        }


def rotate_secret(
    client: hvac.Client,
    ns_config: NamespaceConfig,
    path: str,
    key: str,
    new_value: str | None = None,
) -> RotationResult:
    """Rotate a single secret key at the given KV-v2 path."""
    value = new_value or generate_secret()
    try:
        existing = client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=ns_config.mount
        )
        data: dict[str, Any] = existing["data"]["data"].copy()
        data[key] = value
        client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=data, mount_point=ns_config.mount
        )
        return RotationResult(
            namespace=ns_config.name, path=path, key=key, success=True
        )
    except Exception as exc:  # noqa: BLE001
        return RotationResult(
            namespace=ns_config.name,
            path=path,
            key=key,
            success=False,
            error=str(exc),
        )


def rotate_namespace(
    client: hvac.Client,
    ns_config: NamespaceConfig,
    targets: list[dict[str, str]],
) -> RotationReport:
    """Rotate multiple secrets within a namespace.

    Each entry in *targets* must have ``path`` and ``key``.
    """
    report = RotationReport()
    for target in targets:
        result = rotate_secret(
            client, ns_config, target["path"], target["key"]
        )
        report.results.append(result)
    return report
