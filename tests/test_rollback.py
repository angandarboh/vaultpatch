"""Tests for vaultpatch.rollback and cli_rollback."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.config import NamespaceConfig, VaultPatchConfig
from vaultpatch.rollback import rollback_snapshot, RollbackReport
from vaultpatch.snapshot import Snapshot, SnapshotEntry
from vaultpatch.cli_rollback import rollback_cmd


@pytest.fixture()
def ns_config():
    return NamespaceConfig(
        name="prod",
        url="https://vault.example.com",
        token="root",
        paths=["secret/app"],
    )


@pytest.fixture()
def sample_snapshot():
    return Snapshot(
        entries=[
            SnapshotEntry(namespace="prod", path="secret/app", data={"key": "old"}),
            SnapshotEntry(namespace="staging", path="secret/app", data={"key": "s"}),
        ]
    )


@pytest.fixture()
def vault_client():
    client = MagicMock()
    client.secrets.kv.v2.create_or_update_secret.return_value = {}
    return client


def test_rollback_filters_by_namespace(vault_client, sample_snapshot):
    report = rollback_snapshot(vault_client, sample_snapshot, "prod")
    assert len(report.results) == 1
    assert report.results[0].path == "secret/app"
    assert report.results[0].namespace == "prod"


def test_rollback_success(vault_client, sample_snapshot):
    report = rollback_snapshot(vault_client, sample_snapshot, "prod")
    assert len(report.successes()) == 1
    assert len(report.failed()) == 0


def test_rollback_dry_run_does_not_call_vault(vault_client, sample_snapshot):
    report = rollback_snapshot(vault_client, sample_snapshot, "prod", dry_run=True)
    vault_client.secrets.kv.v2.create_or_update_secret.assert_not_called()
    assert len(report.successes()) == 1


def test_rollback_records_error_on_exception(sample_snapshot):
    bad_client = MagicMock()
    bad_client.secrets.kv.v2.create_or_update_secret.side_effect = RuntimeError("boom")
    report = rollback_snapshot(bad_client, sample_snapshot, "prod")
    assert len(report.failed()) == 1
    assert "boom" in report.failed()[0].error


def test_rollback_summary_string(vault_client, sample_snapshot):
    report = rollback_snapshot(vault_client, sample_snapshot, "prod")
    summary = report.summary()
    assert "1/1" in summary
    assert "0 failed" in summary


# ── CLI tests ────────────────────────────────────────────────────────────────

@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def vault_cfg(ns_config):
    return VaultPatchConfig(namespaces=[ns_config])


@pytest.fixture()
def snapshot_file(tmp_path, sample_snapshot):
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(sample_snapshot.to_dict()))
    return str(p)


def test_rollback_cmd_missing_config(runner, snapshot_file):
    result = runner.invoke(rollback_cmd, [snapshot_file, "--config", "no_file.yaml"])
    assert result.exit_code != 0


def test_rollback_cmd_dry_run(runner, snapshot_file, vault_cfg, tmp_path):
    cfg_path = tmp_path / "vaultpatch.yaml"
    cfg_path.write_text("namespaces:\n  - name: prod\n    url: https://v\n    token: t\n    paths: [secret/app]\n")
    with patch("vaultpatch.cli_rollback.load_config", return_value=vault_cfg), \
         patch("vaultpatch.cli_rollback.build_client") as mock_build:
        mock_build.return_value = MagicMock()
        result = runner.invoke(
            rollback_cmd,
            [snapshot_file, "--config", str(cfg_path), "--dry-run"],
        )
    assert "dry-run" in result.output
    assert result.exit_code == 0
