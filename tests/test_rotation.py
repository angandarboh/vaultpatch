"""Tests for vaultpatch.rotation."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vaultpatch.config import NamespaceConfig
from vaultpatch.rotation import (
    RotationReport,
    RotationResult,
    generate_secret,
    rotate_namespace,
    rotate_secret,
)


@pytest.fixture()
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(name="dev", url="https://vault.dev", mount="secret")


@pytest.fixture()
def vault_client(ns_config: NamespaceConfig) -> MagicMock:
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"password": "old", "token": "old-token"}}
    }
    return client


def test_generate_secret_length() -> None:
    s = generate_secret(24)
    assert len(s) == 24


def test_generate_secret_uniqueness() -> None:
    assert generate_secret() != generate_secret()


def test_rotate_secret_success(ns_config, vault_client) -> None:
    result = rotate_secret(vault_client, ns_config, "app/db", "password")
    assert result.success is True
    assert result.namespace == "dev"
    assert result.path == "app/db"
    assert result.key == "password"
    assert result.error is None
    vault_client.secrets.kv.v2.create_or_update_secret.assert_called_once()


def test_rotate_secret_uses_provided_value(ns_config, vault_client) -> None:
    rotate_secret(vault_client, ns_config, "app/db", "password", new_value="fixed")
    call_kwargs = vault_client.secrets.kv.v2.create_or_update_secret.call_args.kwargs
    assert call_kwargs["secret"]["password"] == "fixed"


def test_rotate_secret_preserves_other_keys(ns_config, vault_client) -> None:
    rotate_secret(vault_client, ns_config, "app/db", "password", new_value="new")
    call_kwargs = vault_client.secrets.kv.v2.create_or_update_secret.call_args.kwargs
    assert "token" in call_kwargs["secret"]


def test_rotate_secret_failure(ns_config) -> None:
    bad_client = MagicMock()
    bad_client.secrets.kv.v2.read_secret_version.side_effect = Exception("forbidden")
    result = rotate_secret(bad_client, ns_config, "app/db", "password")
    assert result.success is False
    assert "forbidden" in result.error


def test_rotation_report_summary(ns_config, vault_client) -> None:
    targets = [{"path": "app/db", "key": "password"}, {"path": "app/db", "key": "token"}]
    report = rotate_namespace(vault_client, ns_config, targets)
    summary = report.summary()
    assert summary["total"] == 2
    assert summary["succeeded"] == 2
    assert summary["failed"] == 0


def test_rotation_report_failures() -> None:
    r1 = RotationResult(namespace="dev", path="p", key="k", success=True)
    r2 = RotationResult(namespace="dev", path="p", key="k2", success=False, error="err")
    report = RotationReport(results=[r1, r2])
    assert len(report.failures()) == 1
    assert report.failures()[0].key == "k2"
