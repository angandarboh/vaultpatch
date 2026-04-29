"""Tests for vaultpatch.cli_diff sub-command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.cli_diff import diff_cmd
from vaultpatch.config import VaultPatchConfig, NamespaceConfig


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def ns_config():
    return NamespaceConfig(
        name="prod",
        url="https://vault.example.com",
        token="root",
        mount="secret",
        secret_paths=["app/db"],
    )


@pytest.fixture()
def vault_cfg(ns_config):
    return VaultPatchConfig(namespaces=[ns_config])


def test_diff_cmd_missing_config(runner, tmp_path):
    result = runner.invoke(diff_cmd, ["--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code != 0
    assert "error" in result.output.lower() or "error" in (result.stderr or "")


def test_diff_cmd_no_matching_namespace(runner, tmp_path, vault_cfg):
    with patch("vaultpatch.cli_diff.load_config", return_value=vault_cfg):
        result = runner.invoke(diff_cmd, ["--namespace", "nonexistent"])
    assert result.exit_code == 0
    assert "No matching" in result.output


def test_diff_cmd_prints_diff_entries(runner, vault_cfg):
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"password": "old_pass"}}
    }

    with patch("vaultpatch.cli_diff.load_config", return_value=vault_cfg), \
         patch("vaultpatch.cli_diff.build_client", return_value=mock_client), \
         patch("vaultpatch.cli_diff.generate_secret", return_value="new_pass"):
        result = runner.invoke(diff_cmd, [])

    assert result.exit_code == 0
    assert "password" in result.output
    assert "Summary:" in result.output


def test_diff_cmd_client_error_continues(runner, vault_cfg):
    from vaultpatch.client import ClientError

    with patch("vaultpatch.cli_diff.load_config", return_value=vault_cfg), \
         patch("vaultpatch.cli_diff.build_client", side_effect=ClientError("auth failed")):
        result = runner.invoke(diff_cmd, [])

    assert "auth failed" in result.output or result.exit_code == 0


def test_diff_cmd_empty_current_data(runner, vault_cfg):
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("not found")

    with patch("vaultpatch.cli_diff.load_config", return_value=vault_cfg), \
         patch("vaultpatch.cli_diff.build_client", return_value=mock_client):
        result = runner.invoke(diff_cmd, [])

    assert result.exit_code == 0
    assert "Nothing to diff" in result.output or "Summary" in result.output
