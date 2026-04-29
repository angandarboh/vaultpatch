"""Secret diff utilities: compare current vs proposed secret values across namespaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SecretDiff:
    """Represents the diff between an existing and proposed secret value."""

    namespace: str
    path: str
    key: str
    old_value: Optional[str]
    new_value: str

    @property
    def changed(self) -> bool:
        return self.old_value != self.new_value

    @property
    def is_new(self) -> bool:
        return self.old_value is None

    def masked(self) -> "SecretDiff":
        """Return a copy with values replaced by masked placeholders."""
        return SecretDiff(
            namespace=self.namespace,
            path=self.path,
            key=self.key,
            old_value="***" if self.old_value is not None else None,
            new_value="***",
        )


@dataclass
class DiffReport:
    """Aggregated diff results for a rotation dry-run."""

    diffs: List[SecretDiff] = field(default_factory=list)

    @property
    def changed(self) -> List[SecretDiff]:
        return [d for d in self.diffs if d.changed]

    @property
    def unchanged(self) -> List[SecretDiff]:
        return [d for d in self.diffs if not d.changed]

    @property
    def new_secrets(self) -> List[SecretDiff]:
        return [d for d in self.diffs if d.is_new]

    def summary(self) -> Dict[str, int]:
        return {
            "total": len(self.diffs),
            "changed": len(self.changed),
            "unchanged": len(self.unchanged),
            "new": len(self.new_secrets),
        }


def build_diff(
    namespace: str,
    path: str,
    proposed: Dict[str, str],
    current: Optional[Dict[str, str]] = None,
) -> List[SecretDiff]:
    """Build a list of SecretDiff entries comparing proposed vs current secrets."""
    current = current or {}
    return [
        SecretDiff(
            namespace=namespace,
            path=path,
            key=key,
            old_value=current.get(key),
            new_value=value,
        )
        for key, value in proposed.items()
    ]
