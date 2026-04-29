"""Tests for the audit CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.cli_audit import audit_cmd
from vaultpatch.config import NamespaceConfig, VaultPatchConfig


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(
        name="prod",
        url="https://vault.example.com",
        token="root",
        mount="secret",
        secret_paths=["app/db", "app/api"],
    )


@pytest.fixture()
def vault_cfg(ns_config: NamespaceConfig) -> VaultPatchConfig:
    return VaultPatchConfig(namespaces=[ns_config])


def test_audit_cmd_missing_config(runner: CliRunner) -> None:
    result = runner.invoke(audit_cmd, ["--config", "nonexistent.yaml"])
    assert result.exit_code == 1
    assert "Config error" in result.output or "Config error" in (result.stderr or "")


def test_audit_cmd_no_matching_namespace(
    runner: CliRunner, vault_cfg: VaultPatchConfig, tmp_path: Path
) -> None:
    cfg_file = tmp_path / "vaultpatch.yaml"
    cfg_file.write_text(
        "namespaces:\n"
        "  - name: prod\n"
        "    url: https://vault.example.com\n"
        "    token: root\n"
        "    mount: secret\n"
        "    secret_paths: [app/db]\n"
    )
    result = runner.invoke(
        audit_cmd, ["--config", str(cfg_file), "--namespace", "staging"]
    )
    assert result.exit_code == 1


def test_audit_cmd_success(
    runner: CliRunner, vault_cfg: VaultPatchConfig, tmp_path: Path
) -> None:
    cfg_file = tmp_path / "vaultpatch.yaml"
    cfg_file.write_text(
        "namespaces:\n"
        "  - name: prod\n"
        "    url: https://vault.example.com\n"
        "    token: root\n"
        "    mount: secret\n"
        "    secret_paths: [app/db]\n"
    )

    mock_metadata = {
        "data": {
            "versions": {
                "1": {"created_time": "2024-01-01T00:00:00Z", "destroyed": False}
            }
        }
    }
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_metadata.return_value = mock_metadata

    with patch("vaultpatch.cli_audit.build_client", return_value=mock_client):
        result = runner.invoke(audit_cmd, ["--config", str(cfg_file)])

    assert result.exit_code == 0
    assert "Total secrets audited" in result.output


def test_audit_cmd_fail_on_stale_exits_2(
    runner: CliRunner, tmp_path: Path
) -> None:
    cfg_file = tmp_path / "vaultpatch.yaml"
    cfg_file.write_text(
        "namespaces:\n"
        "  - name: prod\n"
        "    url: https://vault.example.com\n"
        "    token: root\n"
        "    mount: secret\n"
        "    secret_paths: [app/db]\n"
    )

    stale_result = MagicMock()
    stale_result.namespace = "prod"
    stale_result.path = "app/db"
    stale_result.last_rotated_at = "2023-01-01T00:00:00Z"

    mock_report = MagicMock()
    mock_report.summary.return_value = {"total": 1, "stale": 1, "errors": 0}

    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_metadata.return_value = {}

    with patch("vaultpatch.cli_audit.build_client", return_value=mock_client), \
         patch("vaultpatch.cli_audit.AuditReport", return_value=mock_report), \
         patch("vaultpatch.cli_audit.stale_secrets", return_value=[stale_result]):
        result = runner.invoke(
            audit_cmd, ["--config", str(cfg_file), "--fail-on-stale"]
        )

    assert result.exit_code == 2
