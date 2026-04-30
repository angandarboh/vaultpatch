"""Rollback support: restore secrets to a previous snapshot state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import hvac

from vaultpatch.snapshot import Snapshot, SnapshotEntry


@dataclass
class RollbackResult:
    path: str
    namespace: str
    success: bool
    error: Optional[str] = None


@dataclass
class RollbackReport:
    results: List[RollbackResult] = field(default_factory=list)

    def failed(self) -> List[RollbackResult]:
        return [r for r in self.results if not r.success]

    def successes(self) -> List[RollbackResult]:
        return [r for r in self.results if r.success]

    def summary(self) -> str:
        total = len(self.results)
        ok = len(self.successes())
        fail = len(self.failed())
        return f"Rollback complete: {ok}/{total} restored, {fail} failed."


def rollback_snapshot(
    client: hvac.Client,
    snapshot: Snapshot,
    namespace: str,
    dry_run: bool = False,
) -> RollbackReport:
    """Restore all entries in *snapshot* that belong to *namespace*."""
    report = RollbackReport()

    entries: List[SnapshotEntry] = [
        e for e in snapshot.entries if e.namespace == namespace
    ]

    for entry in entries:
        if dry_run:
            report.results.append(
                RollbackResult(path=entry.path, namespace=namespace, success=True)
            )
            continue
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=entry.path,
                secret=entry.data,
            )
            report.results.append(
                RollbackResult(path=entry.path, namespace=namespace, success=True)
            )
        except Exception as exc:  # noqa: BLE001
            report.results.append(
                RollbackResult(
                    path=entry.path,
                    namespace=namespace,
                    success=False,
                    error=str(exc),
                )
            )

    return report
