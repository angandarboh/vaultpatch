"""Tests for vaultpatch.config module."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vaultpatch.config import ConfigError, load_config


@pytest.fixture()
def config_file(tmp_path: Path):
    """Write a minimal valid config and return its path."""

    def _write(content: str) -> Path:
        p = tmp_path / "vaultpatch.yaml"
        p.write_text(textwrap.dedent(content))
        return p

    return _write


VALID_YAML = """
    namespaces:
      - name: prod
        address: https://vault.prod.example.com
        token_env: VAULT_TOKEN_PROD
        secret_paths:
          - secret/data/db/password
          - secret/data/api/key
        auth_method: token
      - name: staging
        address: https://vault.staging.example.com
        token_env: VAULT_TOKEN_STAGING
    dry_run: true
    audit_log: /var/log/vaultpatch/audit.log
"""


def test_load_valid_config(config_file):
    cfg = load_config(config_file(VALID_YAML))
    assert len(cfg.namespaces) == 2
    assert cfg.namespaces[0].name == "prod"
    assert cfg.namespaces[0].address == "https://vault.prod.example.com"
    assert cfg.namespaces[0].token_env == "VAULT_TOKEN_PROD"
    assert cfg.namespaces[0].secret_paths == [
        "secret/data/db/password",
        "secret/data/api/key",
    ]
    assert cfg.namespaces[1].auth_method == "token"  # default
    assert cfg.dry_run is True
    assert cfg.audit_log == "/var/log/vaultpatch/audit.log"


def test_missing_config_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/path/vaultpatch.yaml")


def test_missing_namespaces_key(config_file):
    with pytest.raises(ConfigError, match="at least one namespace"):
        load_config(config_file("dry_run: false\n"))


def test_namespace_missing_required_field(config_file):
    yaml_content = """
        namespaces:
          - name: broken
            address: https://vault.example.com
    """
    with pytest.raises(ConfigError, match="token_env"):
        load_config(config_file(yaml_content))


def test_default_values(config_file):
    yaml_content = """
        namespaces:
          - name: dev
            address: https://vault.dev.example.com
            token_env: VAULT_TOKEN_DEV
    """
    cfg = load_config(config_file(yaml_content))
    ns = cfg.namespaces[0]
    assert ns.secret_paths == []
    assert ns.auth_method == "token"
    assert cfg.dry_run is False
    assert cfg.audit_log is None


def test_invalid_top_level_type(config_file):
    with pytest.raises(ConfigError, match="YAML mapping"):
        load_config(config_file("- just\n- a\n- list\n"))
