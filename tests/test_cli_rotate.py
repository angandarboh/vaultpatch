"""Tests for vaultpatch.cli_rotate."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.cli_rotate import rotate_cmd, _group_by_namespace
from vaultpatch.config import NamespaceConfig, VaultPatchConfig
from vaultpatch.rotation import RotationReport


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(
        name="dev",
        url="https://vault.dev.example.com",
        auth_method="token",
        secret_paths=["secret/app/db", "secret/app/api"],
    )


@pytest.fixture()
def vault_cfg(ns_config: NamespaceConfig, tmp_path: Path) -> Path:
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "namespaces:\n"
        "  - name: dev\n"
        "    url: https://vault.dev.example.com\n"
        "    auth_method: token\n"
        "    secret_paths:\n"
        "      - secret/app/db\n"
        "      - secret/app/api\n"
    )
    return cfg_file


def test_rotate_cmd_missing_config(runner: CliRunner) -> None:
    result = runner.invoke(rotate_cmd, ["--config", "/nonexistent/config.yaml"])
    assert result.exit_code != 0
    assert "Config error" in result.output or result.exit_code == 1


def test_rotate_cmd_no_matching_namespace(runner: CliRunner, vault_cfg: Path) -> None:
    result = runner.invoke(
        rotate_cmd, ["--config", str(vault_cfg), "--namespace", "prod"]
    )
    assert result.exit_code == 1
    assert "No namespace matching 'prod'" in result.output


def test_rotate_cmd_dry_run(runner: CliRunner, vault_cfg: Path, ns_config: NamespaceConfig) -> None:
    ok_report = RotationReport(namespace=ns_config.name, path="secret/app/db", success=True, error=None)

    with patch("vaultpatch.cli_rotate.load_config") as mock_cfg, \
         patch("vaultpatch.cli_rotate.build_client") as mock_client, \
         patch("vaultpatch.cli_rotate.rotate_secret", return_value=ok_report) as mock_rotate:
        mock_cfg.return_value = VaultPatchConfig(namespaces=[ns_config])
        mock_client.return_value = MagicMock()
        result = runner.invoke(rotate_cmd, ["--config", str(vault_cfg), "--dry-run"])

    assert result.exit_code == 0
    assert "dry-run" in result.output
    assert "2/2 rotated" in result.output


def test_rotate_cmd_reports_failures(runner: CliRunner, vault_cfg: Path, ns_config: NamespaceConfig) -> None:
    fail_report = RotationReport(
        namespace=ns_config.name, path="secret/app/db", success=False, error="permission denied"
    )

    with patch("vaultpatch.cli_rotate.load_config") as mock_cfg, \
         patch("vaultpatch.cli_rotate.build_client") as mock_client, \
         patch("vaultpatch.cli_rotate.rotate_secret", return_value=fail_report):
        mock_cfg.return_value = VaultPatchConfig(namespaces=[ns_config])
        mock_client.return_value = MagicMock()
        result = runner.invoke(rotate_cmd, ["--config", str(vault_cfg)])

    assert result.exit_code == 2
    assert "FAIL" in result.output
    assert "permission denied" in result.output


def test_group_by_namespace(ns_config: NamespaceConfig) -> None:
    other = NamespaceConfig(
        name="staging",
        url="https://vault.staging.example.com",
        auth_method="token",
        secret_paths=["secret/x"],
    )
    groups = _group_by_namespace([ns_config, other])
    assert len(groups) == 2
    assert "https://vault.dev.example.com" in groups
