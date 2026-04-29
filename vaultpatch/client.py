"""Vault client factory for vaultpatch."""
from __future__ import annotations

import os

import hvac

from vaultpatch.config import NamespaceConfig

_TOKEN_ENV = "VAULT_TOKEN"
_ROLE_ID_ENV = "VAULT_ROLE_ID"
_SECRET_ID_ENV = "VAULT_SECRET_ID"


class ClientError(Exception):
    """Raised when a Vault client cannot be created or authenticated."""


def _token_from_env() -> str | None:
    return os.environ.get(_TOKEN_ENV)


def build_client(ns_config: NamespaceConfig) -> hvac.Client:
    """Build and authenticate an hvac client for *ns_config*.

    Authentication priority:
    1. Token from ``VAULT_TOKEN`` env var.
    2. AppRole using ``VAULT_ROLE_ID`` + ``VAULT_SECRET_ID`` env vars.

    Raises :class:`ClientError` if authentication fails or no credentials
    are available.
    """
    client = hvac.Client(
        url=ns_config.url,
        namespace=getattr(ns_config, "namespace", None),
    )

    token = _token_from_env()
    if token:
        client.token = token
        if not client.is_authenticated():
            raise ClientError(
                f"Token authentication failed for namespace '{ns_config.name}'."
            )
        return client

    role_id = os.environ.get(_ROLE_ID_ENV)
    secret_id = os.environ.get(_SECRET_ID_ENV)
    if role_id and secret_id:
        resp = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        client.token = resp["auth"]["client_token"]
        if not client.is_authenticated():
            raise ClientError(
                f"AppRole authentication failed for namespace '{ns_config.name}'."
            )
        return client

    raise ClientError(
        "No Vault credentials found. Set VAULT_TOKEN or "
        "VAULT_ROLE_ID + VAULT_SECRET_ID environment variables."
    )
