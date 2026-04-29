"""Tests for vaultpatch.audit module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from vaultpatch.audit import (
    AuditReport,
    SecretAuditResult,
    _audit_path,
    audit_namespace,
)
from vaultpatch.config import NamespaceConfig


@pytest.fixture()
def ns_config() -> NamespaceConfig:
    return NamespaceConfig(
        name="prod",
        url="https://vault.example.com",
        token="s.testtoken",
        namespace="prod",
        secret_paths=["secret/db", "secret/api"],
    )


def _make_metadata(age_days: float) -> dict:
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {
        "data": {
            "versions": {
                "1": {"created_time": created.strftime("%Y-%m-%dT%H:%M:%S.000000Z")}
            }
        }
    }


# --- AuditReport ---

def test_audit_report_stale_filter():
    results = [
        SecretAuditResult("ns", "p1", None, 10.0, False),
        SecretAuditResult("ns", "p2", None, 95.0, True),
        SecretAuditResult("ns", "p3", None, None, False, error="oops"),
    ]
    report = AuditReport(results=results)
    assert len(report.stale_secrets) == 1
    assert report.stale_secrets[0].path == "p2"


def test_audit_report_errors_filter():
    results = [
        SecretAuditResult("ns", "p1", None, 5.0, False),
        SecretAuditResult("ns", "p2", None, None, False, error="timeout"),
    ]
    report = AuditReport(results=results)
    assert len(report.errors) == 1
    assert "timeout" in report.errors[0].error


def test_audit_report_summary_contains_counts():
    results = [
        SecretAuditResult("ns", "p1", None, 5.0, False),
        SecretAuditResult("ns", "p2", None, 100.0, True),
    ]
    report = AuditReport(results=results)
    summary = report.summary()
    assert "Total secrets scanned : 2" in summary
    assert "Stale secrets         : 1" in summary
    assert "Errors                : 0" in summary


# --- _audit_path ---

def test_audit_path_fresh_secret():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_metadata.return_value = _make_metadata(10)
    result = _audit_path(mock_client, "prod", "secret/db", max_age_days=90)
    assert result.error is None
    assert result.age_days is not None and result.age_days < 90
    assert result.exceeds_max_age is False


def test_audit_path_stale_secret():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_metadata.return_value = _make_metadata(120)
    result = _audit_path(mock_client, "prod", "secret/db", max_age_days=90)
    assert result.exceeds_max_age is True
    assert result.age_days > 90


def test_audit_path_vault_error():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_metadata.side_effect = Exception("403 Forbidden")
    result = _audit_path(mock_client, "prod", "secret/missing", max_age_days=90)
    assert result.error is not None
    assert "403" in result.error
    assert result.exceeds_max_age is False


# --- audit_namespace ---

@patch("vaultpatch.audit._get_client")
def test_audit_namespace_returns_results(mock_get_client, ns_config):
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_metadata.return_value = _make_metadata(5)
    mock_get_client.return_value = mock_client

    results = audit_namespace(ns_config, max_age_days=90)
    assert len(results) == len(ns_config.secret_paths)
    assert all(r.error is None for r in results)


@patch("vaultpatch.audit._get_client", side_effect=PermissionError("auth failed"))
def test_audit_namespace_connection_error(mock_get_client, ns_config):
    results = audit_namespace(ns_config, max_age_days=90)
    assert len(results) == 1
    assert results[0].error is not None
    assert "auth failed" in results[0].error
