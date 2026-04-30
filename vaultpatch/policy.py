"""Policy validation module for vaultpatch.

Checks that secrets in Vault namespaces conform to defined
length, character-set, and rotation-age policies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from vaultpatch.config import NamespaceConfig


@dataclass
class PolicyViolation:
    path: str
    key: str
    reason: str
    namespace: str


@dataclass
class PolicyReport:
    violations: List[PolicyViolation] = field(default_factory=list)
    checked: int = 0

    def failed(self) -> List[PolicyViolation]:
        return list(self.violations)

    def passed(self) -> bool:
        return len(self.violations) == 0

    def summary(self) -> str:
        total = self.checked
        bad = len(self.violations)
        ok = total - bad
        return f"Checked {total} secret(s): {ok} passed, {bad} violation(s)."


def _age_days(created_time: Optional[str]) -> Optional[float]:
    """Return age in days from an ISO-8601 Vault metadata timestamp."""
    if not created_time:
        return None
    try:
        dt = datetime.fromisoformat(created_time.rstrip("Z")).replace(
            tzinfo=timezone.utc
        )
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except ValueError:
        return None


def validate_secrets(
    ns_config: NamespaceConfig,
    secrets: dict,
    metadata: Optional[dict] = None,
) -> PolicyReport:
    """Validate *secrets* dict against policies in *ns_config*.

    Args:
        ns_config: namespace configuration (may carry policy hints via extra fields).
        secrets: mapping of {path: {key: value}}.
        metadata: optional mapping of {path: vault_metadata_dict}.

    Returns:
        A :class:`PolicyReport` with any violations found.
    """
    report = PolicyReport()
    min_length: int = getattr(ns_config, "min_secret_length", 16)
    max_age_days: Optional[int] = getattr(ns_config, "max_secret_age_days", None)
    allowed_pattern: Optional[str] = getattr(ns_config, "secret_pattern", None)
    compiled = re.compile(allowed_pattern) if allowed_pattern else None

    for path, kv in secrets.items():
        for key, value in kv.items():
            report.checked += 1
            str_val = str(value)

            if len(str_val) < min_length:
                report.violations.append(
                    PolicyViolation(
                        path=path,
                        key=key,
                        reason=f"value length {len(str_val)} < minimum {min_length}",
                        namespace=ns_config.name,
                    )
                )
            elif compiled and not compiled.fullmatch(str_val):
                report.violations.append(
                    PolicyViolation(
                        path=path,
                        key=key,
                        reason=f"value does not match required pattern '{allowed_pattern}'",
                        namespace=ns_config.name,
                    )
                )

        if max_age_days and metadata:
            meta = metadata.get(path, {})
            created = meta.get("created_time")
            age = _age_days(created)
            if age is not None and age > max_age_days:
                report.violations.append(
                    PolicyViolation(
                        path=path,
                        key="<secret>",
                        reason=f"secret age {age:.1f}d exceeds max {max_age_days}d",
                        namespace=ns_config.name,
                    )
                )
                report.checked += 1

    return report
