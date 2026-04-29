"""Tests for vaultpatch.diff module."""

from __future__ import annotations

import pytest

from vaultpatch.diff import DiffReport, SecretDiff, build_diff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_diff(old: str | None, new: str, key: str = "token") -> SecretDiff:
    return SecretDiff(namespace="ns1", path="secret/app", key=key, old_value=old, new_value=new)


# ---------------------------------------------------------------------------
# SecretDiff
# ---------------------------------------------------------------------------

def test_changed_when_values_differ():
    d = _make_diff(old="abc", new="xyz")
    assert d.changed is True


def test_unchanged_when_values_equal():
    d = _make_diff(old="same", new="same")
    assert d.changed is False


def test_is_new_when_old_is_none():
    d = _make_diff(old=None, new="fresh")
    assert d.is_new is True


def test_is_not_new_when_old_exists():
    d = _make_diff(old="old", new="new")
    assert d.is_new is False


def test_masked_hides_values():
    d = _make_diff(old="secret", new="newsecret")
    m = d.masked()
    assert m.old_value == "***"
    assert m.new_value == "***"
    assert m.key == d.key


def test_masked_old_none_stays_none():
    d = _make_diff(old=None, new="newsecret")
    m = d.masked()
    assert m.old_value is None


# ---------------------------------------------------------------------------
# build_diff
# ---------------------------------------------------------------------------

def test_build_diff_detects_new_keys():
    diffs = build_diff("ns", "secret/app", proposed={"key": "val"}, current={})
    assert len(diffs) == 1
    assert diffs[0].is_new is True


def test_build_diff_detects_changed_keys():
    diffs = build_diff("ns", "secret/app", proposed={"key": "new"}, current={"key": "old"})
    assert diffs[0].changed is True


def test_build_diff_no_current_treats_all_as_new():
    diffs = build_diff("ns", "secret/app", proposed={"a": "1", "b": "2"})
    assert all(d.is_new for d in diffs)


# ---------------------------------------------------------------------------
# DiffReport
# ---------------------------------------------------------------------------

def test_diff_report_summary_counts():
    report = DiffReport(diffs=[
        _make_diff(old=None, new="v1", key="k1"),
        _make_diff(old="old", new="new", key="k2"),
        _make_diff(old="same", new="same", key="k3"),
    ])
    s = report.summary()
    assert s["total"] == 3
    assert s["new"] == 1
    assert s["changed"] == 2  # new secrets are also changed
    assert s["unchanged"] == 1


def test_diff_report_empty():
    report = DiffReport()
    assert report.summary() == {"total": 0, "changed": 0, "unchanged": 0, "new": 0}
