"""Snapshot support: capture and restore Vault secret state for a namespace."""
from __future__ import annotations

import json
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import hvac

from vaultpatch.config import NamespaceConfig


@dataclass
class SnapshotEntry:
    path: str
    data: Dict[str, str]
    captured_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat()
    )


@dataclass
class Snapshot:
    namespace: str
    entries: List[SnapshotEntry] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "namespace": self.namespace,
            "created_at": self.created_at,
            "entries": [
                {"path": e.path, "data": e.data, "captured_at": e.captured_at}
                for e in self.entries
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        entries = [
            SnapshotEntry(path=e["path"], data=e["data"], captured_at=e["captured_at"])
            for e in data.get("entries", [])
        ]
        return cls(
            namespace=data["namespace"],
            entries=entries,
            created_at=data["created_at"],
        )


def capture_snapshot(
    client: hvac.Client, ns_config: NamespaceConfig, paths: List[str]
) -> Snapshot:
    """Read each secret path and build a Snapshot."""
    snapshot = Snapshot(namespace=ns_config.name)
    for path in paths:
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=ns_config.mount
            )
            secret_data = resp["data"]["data"]
        except Exception:
            secret_data = {}
        snapshot.entries.append(SnapshotEntry(path=path, data=secret_data))
    return snapshot


def save_snapshot(snapshot: Snapshot, dest: Path) -> None:
    dest.write_text(json.dumps(snapshot.to_dict(), indent=2))


def load_snapshot(src: Path) -> Snapshot:
    return Snapshot.from_dict(json.loads(src.read_text()))


def restore_snapshot(
    client: hvac.Client, ns_config: NamespaceConfig, snapshot: Snapshot
) -> List[str]:
    """Write each snapshot entry back to Vault. Returns list of failed paths."""
    failed: List[str] = []
    for entry in snapshot.entries:
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=entry.path,
                secret=entry.data,
                mount_point=ns_config.mount,
            )
        except Exception:
            failed.append(entry.path)
    return failed
