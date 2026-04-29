"""Tests for vaultpatch.rotation."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vaultpatch.config import NamespaceConfig
from vaultpatch.rotation import (
    generate_secret,
    rotate_secret,
    RotationReport,
    RotationResult,
    _split_mount,
)


@pytest.fixture
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(
        name="prod",
        url="https://vault.example.com",
        token="root",
        path_prefix="secret/",
    )


@pytest.fixture
def vault_client() -> MagicMock:
    client = MagicMock()
    client.secrets.kv.v2.create_or_update_secret.return_value = {"data": {}}
    return client


# --- generate_secret ---

def test_generate_secret_length():
    assert len(generate_secret(24)) == 24


def test_generate_secret_default_length():
    assert len(generate_secret()) == 32


def test_generate_secret_uniqueness():
    values = {generate_secret() for _ in range(20)}
    assert len(values) == 20


def test_generate_secret_minimum_length_enforced():
    with pytest.raises(ValueError, match="at least 8"):
        generate_secret(4)


# --- _split_mount ---

def test_split_mount_basic():
    mount, path = _split_mount("secret/myapp/db")
    assert mount == "secret"
    assert path == "myapp/db"


def test_split_mount_leading_slash():
    mount, path = _split_mount("/kv/service/key")
    assert mount == "kv"
    assert path == "service/key"


def test_split_mount_no_subpath_raises():
    with pytest.raises(ValueError):
        _split_mount("onlymount")


# --- rotate_secret ---

def test_rotate_secret_success(ns_config, vault_client):
    result = rotate_secret(vault_client, ns_config, "secret/app/db")
    assert result.error is None
    assert result.namespace == "prod"
    assert result.path == "secret/app/db"
    assert len(result.new_value) == 32
    vault_client.secrets.kv.v2.create_or_update_secret.assert_called_once()


def test_rotate_secret_vault_error(ns_config, vault_client):
    vault_client.secrets.kv.v2.create_or_update_secret.side_effect = Exception("permission denied")
    result = rotate_secret(vault_client, ns_config, "secret/app/key")
    assert result.error == "permission denied"
    assert result.new_value is None


# --- RotationReport ---

def test_rotation_report_successes_and_failed():
    results = [
        RotationResult(namespace="prod", path="secret/a", new_value="abc"),
        RotationResult(namespace="prod", path="secret/b", error="timeout"),
    ]
    report = RotationReport(results)
    assert len(report.successes()) == 1
    assert len(report.failed()) == 1


def test_rotation_report_summary():
    results = [
        RotationResult(namespace="prod", path="secret/a", new_value="abc"),
        RotationResult(namespace="prod", path="secret/b", new_value="xyz"),
        RotationResult(namespace="prod", path="secret/c", error="denied"),
    ]
    report = RotationReport(results)
    summary = report.summary()
    assert "2 rotated" in summary
    assert "1 failed" in summary


def test_rotation_report_paths_rotated():
    results = [
        RotationResult(namespace="prod", path="secret/x", new_value="val"),
        RotationResult(namespace="prod", path="secret/y", error="err"),
    ]
    report = RotationReport(results)
    assert report.paths_rotated() == ["secret/x"]
