"""Unit tests for vaultpatch.snapshot."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vaultpatch.config import NamespaceConfig
from vaultpatch.snapshot import (
    Snapshot,
    SnapshotEntry,
    capture_snapshot,
    load_snapshot,
    restore_snapshot,
    save_snapshot,
)


@pytest.fixture
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(
        name="prod",
        url="https://vault.example.com",
        token="root",
        mount="secret",
    )


@pytest.fixture
def vault_client() -> MagicMock:
    return MagicMock()


def test_snapshot_roundtrip_dict():
    entry = SnapshotEntry(path="app/db", data={"password": "s3cr3t"}, captured_at="2024-01-01T00:00:00")
    snap = Snapshot(namespace="prod", entries=[entry], created_at="2024-01-01T00:00:00")
    restored = Snapshot.from_dict(snap.to_dict())
    assert restored.namespace == "prod"
    assert len(restored.entries) == 1
    assert restored.entries[0].path == "app/db"
    assert restored.entries[0].data == {"password": "s3cr3t"}


def test_save_and_load_snapshot(tmp_path: Path):
    entry = SnapshotEntry(path="app/key", data={"val": "abc"}, captured_at="2024-01-01T00:00:00")
    snap = Snapshot(namespace="dev", entries=[entry], created_at="2024-01-01T00:00:00")
    dest = tmp_path / "snap.json"
    save_snapshot(snap, dest)
    loaded = load_snapshot(dest)
    assert loaded.namespace == "dev"
    assert loaded.entries[0].data == {"val": "abc"}


def test_capture_snapshot_reads_paths(vault_client, ns_config):
    vault_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"key": "value"}}
    }
    snap = capture_snapshot(vault_client, ns_config, ["app/db", "app/api"])
    assert snap.namespace == "prod"
    assert len(snap.entries) == 2
    assert snap.entries[0].data == {"key": "value"}


def test_capture_snapshot_handles_error(vault_client, ns_config):
    vault_client.secrets.kv.v2.read_secret_version.side_effect = Exception("not found")
    snap = capture_snapshot(vault_client, ns_config, ["missing/path"])
    assert snap.entries[0].data == {}


def test_restore_snapshot_success(vault_client, ns_config):
    snap = Snapshot(
        namespace="prod",
        entries=[SnapshotEntry(path="app/db", data={"pw": "x"}, captured_at="2024-01-01T00:00:00")],
    )
    failed = restore_snapshot(vault_client, ns_config, snap)
    assert failed == []
    vault_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
        path="app/db", secret={"pw": "x"}, mount_point="secret"
    )


def test_restore_snapshot_partial_failure(vault_client, ns_config):
    vault_client.secrets.kv.v2.create_or_update_secret.side_effect = Exception("write error")
    snap = Snapshot(
        namespace="prod",
        entries=[SnapshotEntry(path="app/db", data={"pw": "x"}, captured_at="2024-01-01T00:00:00")],
    )
    failed = restore_snapshot(vault_client, ns_config, snap)
    assert "app/db" in failed
