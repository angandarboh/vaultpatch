"""CLI command: vaultpatch policy — validate secrets against defined policies."""
from __future__ import annotations

import sys
from typing import Optional

import click

from vaultpatch.client import build_client, ClientError
from vaultpatch.config import load_config, ConfigError
from vaultpatch.policy import validate_secrets, PolicyReport


def _print_report(report: PolicyReport, namespace: str) -> None:
    click.echo(f"\n[{namespace}] {report.summary()}")
    for v in report.failed():
        click.echo(
            click.style(f"  VIOLATION ", fg="red")
            + f"{v.path}::{v.key} — {v.reason}"
        )


@click.command("policy")
@click.option("-c", "--config", "config_path", default="vaultpatch.yaml", show_default=True)
@click.option("-n", "--namespace", "namespace_filter", default=None)
@click.option("--fail-on-violation", is_flag=True, default=False,
              help="Exit with code 1 if any violation is found.")
def policy_cmd(
    config_path: str,
    namespace_filter: Optional[str],
    fail_on_violation: bool,
) -> None:
    """Validate secrets in Vault against configured policies."""
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(1)

    namespaces = cfg.namespaces
    if namespace_filter:
        namespaces = [ns for ns in namespaces if ns.name == namespace_filter]
        if not namespaces:
            click.echo(f"No namespace matching '{namespace_filter}' found.", err=True)
            sys.exit(1)

    any_violation = False

    for ns in namespaces:
        try:
            client = build_client(ns)
        except ClientError as exc:
            click.echo(f"[{ns.name}] Client error: {exc}", err=True)
            continue

        secrets: dict = {}
        metadata: dict = {}

        for path in ns.paths:
            try:
                raw = client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=ns.mount
                )
                secrets[path] = raw["data"]["data"]
                meta_raw = client.secrets.kv.v2.read_secret_metadata(
                    path=path, mount_point=ns.mount
                )
                metadata[path] = meta_raw["data"]["versions"].get(
                    str(raw["data"]["metadata"]["version"]), {}
                )
            except Exception as exc:  # noqa: BLE001
                click.echo(f"[{ns.name}] Could not read {path}: {exc}", err=True)

        report = validate_secrets(ns, secrets, metadata)
        _print_report(report, ns.name)

        if not report.passed():
            any_violation = True

    if fail_on_violation and any_violation:
        sys.exit(1)
