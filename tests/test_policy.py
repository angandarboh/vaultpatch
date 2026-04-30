"""Tests for vaultpatch.policy."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from vaultpatch.policy import PolicyViolation, PolicyReport, validate_secrets, _age_days


@pytest.fixture()
def ns_config():
    ns = MagicMock()
    ns.name = "prod"
    ns.min_secret_length = 16
    ns.max_secret_age_days = None
    ns.secret_pattern = None
    return ns


# ---------------------------------------------------------------------------
# _age_days helpers
# ---------------------------------------------------------------------------

def test_age_days_valid_timestamp():
    past = datetime.now(timezone.utc) - timedelta(days=5)
    ts = past.isoformat()
    age = _age_days(ts)
    assert age is not None
    assert 4.9 < age < 5.1


def test_age_days_none_input():
    assert _age_days(None) is None


def test_age_days_invalid_string():
    assert _age_days("not-a-date") is None


# ---------------------------------------------------------------------------
# PolicyReport
# ---------------------------------------------------------------------------

def test_report_passed_when_no_violations():
    report = PolicyReport(checked=3)
    assert report.passed() is True
    assert report.failed() == []


def test_report_failed_returns_violations():
    v = PolicyViolation(path="sec/a", key="pw", reason="too short", namespace="prod")
    report = PolicyReport(violations=[v], checked=1)
    assert not report.passed()
    assert len(report.failed()) == 1


def test_report_summary_counts(ns_config):
    v = PolicyViolation(path="sec/a", key="pw", reason="too short", namespace="prod")
    report = PolicyReport(violations=[v], checked=4)
    summary = report.summary()
    assert "4" in summary
    assert "1" in summary


# ---------------------------------------------------------------------------
# validate_secrets
# ---------------------------------------------------------------------------

def test_no_violations_when_value_long_enough(ns_config):
    secrets = {"secret/myapp": {"password": "a" * 20}}
    report = validate_secrets(ns_config, secrets)
    assert report.passed()
    assert report.checked == 1


def test_violation_when_value_too_short(ns_config):
    secrets = {"secret/myapp": {"password": "short"}}
    report = validate_secrets(ns_config, secrets)
    assert not report.passed()
    assert report.violations[0].key == "password"
    assert "minimum" in report.violations[0].reason


def test_violation_when_pattern_not_matched(ns_config):
    ns_config.secret_pattern = r"[A-Z0-9]{20,}"
    secrets = {"secret/myapp": {"token": "a" * 20}}  # lowercase — fails pattern
    report = validate_secrets(ns_config, secrets)
    assert not report.passed()
    assert "pattern" in report.violations[0].reason


def test_no_violation_when_pattern_matches(ns_config):
    ns_config.secret_pattern = r"[A-Z0-9]{16,}"
    secrets = {"secret/myapp": {"token": "ABCDEFGHIJKLMNOP"}}  # 16 uppercase
    report = validate_secrets(ns_config, secrets)
    assert report.passed()


def test_age_violation_when_secret_too_old(ns_config):
    ns_config.max_secret_age_days = 30
    old_ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    secrets = {"secret/myapp": {"key": "a" * 20}}
    metadata = {"secret/myapp": {"created_time": old_ts}}
    report = validate_secrets(ns_config, secrets, metadata)
    age_violations = [v for v in report.violations if "age" in v.reason]
    assert age_violations, "Expected an age violation"


def test_no_age_violation_when_secret_fresh(ns_config):
    ns_config.max_secret_age_days = 30
    fresh_ts = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    secrets = {"secret/myapp": {"key": "a" * 20}}
    metadata = {"secret/myapp": {"created_time": fresh_ts}}
    report = validate_secrets(ns_config, secrets, metadata)
    age_violations = [v for v in report.violations if "age" in v.reason]
    assert not age_violations


def test_multiple_keys_all_checked(ns_config):
    secrets = {"secret/myapp": {"k1": "a" * 20, "k2": "b" * 20, "k3": "c" * 20}}
    report = validate_secrets(ns_config, secrets)
    assert report.checked == 3
    assert report.passed()
