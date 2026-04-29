"""Tests for vaultpatch.client."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vaultpatch.client import ClientError, build_client
from vaultpatch.config import NamespaceConfig


@pytest.fixture()
def ns() -> NamespaceConfig:
    return NamespaceConfig(name="prod", url="https://vault.prod", mount="secret")


def test_build_client_with_token(ns, monkeypatch) -> None:
    monkeypatch.setenv("VAULT_TOKEN", "root")
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    with patch("vaultpatch.client.hvac.Client", return_value=mock_client):
        client = build_client(ns)
    assert client is mock_client
    assert mock_client.token == "root"


def test_build_client_token_auth_failure(ns, monkeypatch) -> None:
    monkeypatch.setenv("VAULT_TOKEN", "bad-token")
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = False
    with patch("vaultpatch.client.hvac.Client", return_value=mock_client):
        with pytest.raises(ClientError, match="Token authentication failed"):
            build_client(ns)


def test_build_client_approle(ns, monkeypatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.setenv("VAULT_SECRET_ID", "secret-xyz")
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.auth.approle.login.return_value = {"auth": {"client_token": "s.abc"}}
    with patch("vaultpatch.client.hvac.Client", return_value=mock_client):
        client = build_client(ns)
    mock_client.auth.approle.login.assert_called_once_with(
        role_id="role-abc", secret_id="secret-xyz"
    )
    assert client.token == "s.abc"


def test_build_client_no_credentials(ns, monkeypatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)
    mock_client = MagicMock()
    with patch("vaultpatch.client.hvac.Client", return_value=mock_client):
        with pytest.raises(ClientError, match="No Vault credentials found"):
            build_client(ns)
