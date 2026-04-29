"""Integration-style tests for vaultpatch.cli_snapshot using Click test runner."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.cli_snapshot import snapshot_cmd
from vaultpatch.config import NamespaceConfig, VaultPatchConfig
from vaultpatch.snapshot import Snapshot, SnapshotEntry


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(name="prod", url="https://vault.example.com", token="root", mount="secret")


@pytest.fixture
def vault_cfg(ns_config) -> VaultPatchConfig:
    return VaultPatchConfig(namespaces=[ns_config])


@pytest.fixture
def snapshot_file(tmp_path) -> Path:
    snap = Snapshot(
        namespace="prod",
        entries=[SnapshotEntry(path="app/db", data={"pw": "old"}, captured_at="2024-01-01T00:00:00")],
        created_at="2024-01-01T00:00:00",
    )
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(snap.to_dict()))
    return p


def test_capture_missing_config(runner, tmp_path):
    result = runner.invoke(
        snapshot_cmd,
        ["capture", "--config", str(tmp_path / "nope.yaml"), "--namespace", "prod",
         "--paths", "app/db", "--output", str(tmp_path / "out.json")],
    )
    assert result.exit_code != 0


def test_capture_unknown_namespace(runner, tmp_path, vault_cfg):
    cfg_path = tmp_path / "config.yaml"
    with patch("vaultpatch.cli_snapshot.load_config", return_value=vault_cfg):
        result = runner.invoke(
            snapshot_cmd,
            ["capture", "--config", str(cfg_path), "--namespace", "staging",
             "--paths", "app/db", "--output", str(tmp_path / "out.json")],
        )
    assert result.exit_code != 0
    assert "not found" in result.output


def test_restore_dry_run(runner, tmp_path, vault_cfg, snapshot_file):
    with patch("vaultpatch.cli_snapshot.load_config", return_value=vault_cfg):
        result = runner.invoke(
            snapshot_cmd,
            ["restore", "--config", str(tmp_path / "c.yaml"), "--namespace", "prod",
             "--snapshot", str(snapshot_file), "--dry-run"],
        )
    assert result.exit_code == 0
    assert "dry-run" in result.output
    assert "app/db" in result.output


def test_restore_success(runner, tmp_path, vault_cfg, snapshot_file):
    mock_client = MagicMock()
    with patch("vaultpatch.cli_snapshot.load_config", return_value=vault_cfg), \
         patch("vaultpatch.cli_snapshot.build_client", return_value=mock_client):
        result = runner.invoke(
            snapshot_cmd,
            ["restore", "--config", str(tmp_path / "c.yaml"), "--namespace", "prod",
             "--snapshot", str(snapshot_file)],
        )
    assert result.exit_code == 0
    assert "successfully" in result.output
