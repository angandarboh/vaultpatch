"""Audit module for scanning and reporting secret staleness across Vault namespaces."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import hvac

from vaultpatch.config import NamespaceConfig

logger = logging.getLogger(__name__)


@dataclass
class SecretAuditResult:
    namespace: str
    path: str
    last_updated: Optional[datetime]
    age_days: Optional[float]
    exceeds_max_age: bool
    error: Optional[str] = None


@dataclass
class AuditReport:
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    results: List[SecretAuditResult] = field(default_factory=list)

    @property
    def stale_secrets(self) -> List[SecretAuditResult]:
        return [r for r in self.results if r.exceeds_max_age]

    @property
    def errors(self) -> List[SecretAuditResult]:
        return [r for r in self.results if r.error is not None]

    def summary(self) -> str:
        total = len(self.results)
        stale = len(self.stale_secrets)
        errs = len(self.errors)
        return (
            f"Audit completed at {self.generated_at.isoformat()}\n"
            f"  Total secrets scanned : {total}\n"
            f"  Stale secrets         : {stale}\n"
            f"  Errors                : {errs}"
        )


def _get_client(ns_config: NamespaceConfig) -> hvac.Client:
    client = hvac.Client(
        url=ns_config.url,
        token=ns_config.token,
        namespace=ns_config.namespace,
    )
    if not client.is_authenticated():
        raise PermissionError(
            f"Vault authentication failed for namespace '{ns_config.namespace}'"
        )
    return client


def audit_namespace(ns_config: NamespaceConfig, max_age_days: int) -> List[SecretAuditResult]:
    """Scan all configured secret paths in a namespace and return audit results."""
    results: List[SecretAuditResult] = []

    try:
        client = _get_client(ns_config)
    except Exception as exc:  # noqa: BLE001
        logger.error("Cannot connect to namespace '%s': %s", ns_config.namespace, exc)
        return [
            SecretAuditResult(
                namespace=ns_config.namespace,
                path="<connection>",
                last_updated=None,
                age_days=None,
                exceeds_max_age=False,
                error=str(exc),
            )
        ]

    for path in ns_config.secret_paths:
        result = _audit_path(client, ns_config.namespace, path, max_age_days)
        results.append(result)

    return results


def _audit_path(
    client: hvac.Client, namespace: str, path: str, max_age_days: int
) -> SecretAuditResult:
    try:
        metadata = client.secrets.kv.v2.read_secret_metadata(path=path)
        versions = metadata["data"]["versions"]
        if not versions:
            raise ValueError("No versions found")
        latest_key = max(versions.keys(), key=int)
        created_time_str = versions[latest_key]["created_time"]
        last_updated = datetime.fromisoformat(created_time_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - last_updated).total_seconds() / 86400
        exceeds = age_days > max_age_days
        logger.debug("Path '%s' age=%.1f days (limit=%d)", path, age_days, max_age_days)
        return SecretAuditResult(
            namespace=namespace,
            path=path,
            last_updated=last_updated,
            age_days=round(age_days, 2),
            exceeds_max_age=exceeds,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error auditing path '%s': %s", path, exc)
        return SecretAuditResult(
            namespace=namespace,
            path=path,
            last_updated=None,
            age_days=None,
            exceeds_max_age=False,
            error=str(exc),
        )
