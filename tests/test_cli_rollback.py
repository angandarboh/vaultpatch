"""Tests for cli_rollback.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.cli_rollback import rollback_cmd
from vaultpatch.config import NamespaceConfig, VaultPatchConfig
from vaultpatch.rollback import RollbackResult, RollbackReport
from vaultpatch.snapshot import Snapshot, SnapshotEntry


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(
        alias="prod",
        url="https://vault.example.com",
        namespace="prod",
        auth={"method": "token", "token": "test-token"},
        paths=["secret/data/app"],
    )


@pytest.fixture()
def vault_cfg(ns_config: NamespaceConfig) -> VaultPatchConfig:
    return VaultPatchConfig(namespaces=[ns_config])


@pytest.fixture()
def snapshot_file(tmp_path: Path) -> Path:
    data = {
        "entries": [
            {
                "namespace": "prod",
                "path": "secret/data/app",
                "data": {"key": "old-value"},
                "captured_at": "2024-01-01T00:00:00",
            }
        ]
    }
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(data))
    return p


def test_rollback_missing_config(runner: CliRunner, snapshot_file: Path) -> None:
    result = runner.invoke(
        rollback_cmd,
        ["--config", "nonexistent.yaml", "--snapshot", str(snapshot_file)],
    )
    assert result.exit_code == 1
    assert "Config error" in result.output


def test_rollback_missing_snapshot(runner: CliRunner, tmp_path: Path, vault_cfg: VaultPatchConfig) -> None:
    cfg_file = tmp_path / "vaultpatch.yaml"
    cfg_file.write_text("namespaces: []")
    result = runner.invoke(
        rollback_cmd,
        ["--config", str(cfg_file), "--snapshot", str(tmp_path / "missing.json")],
    )
    assert result.exit_code == 1
    assert "not found" in result.output


def test_rollback_dry_run(runner: CliRunner, tmp_path: Path, vault_cfg: VaultPatchConfig, snapshot_file: Path) -> None:
    cfg_file = tmp_path / "vaultpatch.yaml"
    cfg_file.write_text("namespaces: []")

    with patch("vaultpatch.cli_rollback.load_config", return_value=vault_cfg):
        result = runner.invoke(
            rollback_cmd,
            ["--config", str(cfg_file), "--snapshot", str(snapshot_file), "--dry-run"],
        )

    assert result.exit_code == 0
    assert "dry-run" in result.output
    assert "secret/data/app" in result.output


def test_rollback_success(runner: CliRunner, tmp_path: Path, vault_cfg: VaultPatchConfig, snapshot_file: Path) -> None:
    cfg_file = tmp_path / "vaultpatch.yaml"
    cfg_file.write_text("namespaces: []")

    mock_report = RollbackReport(
        results=[
            RollbackResult(namespace="prod", path="secret/data/app", success=True, error=None)
        ]
    )

    with patch("vaultpatch.cli_rollback.load_config", return_value=vault_cfg), \
         patch("vaultpatch.cli_rollback.build_client", return_value=MagicMock()), \
         patch("vaultpatch.cli_rollback.perform_rollback", return_value=mock_report):
        result = runner.invoke(
            rollback_cmd,
            ["--config", str(cfg_file), "--snapshot", str(snapshot_file)],
        )

    assert result.exit_code == 0
    assert "1 succeeded" in result.output
    assert "secret/data/app" in result.output
