"""CLI command for auditing secrets across Vault namespaces."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from vaultpatch.audit import AuditReport, stale_secrets
from vaultpatch.client import ClientError, build_client
from vaultpatch.config import ConfigError, load_config


@click.command("audit")
@click.option(
    "--config",
    "config_path",
    default="vaultpatch.yaml",
    show_default=True,
    help="Path to vaultpatch config file.",
)
@click.option(
    "--namespace",
    "namespace_filter",
    default=None,
    help="Limit audit to a single namespace name.",
)
@click.option(
    "--stale-days",
    default=90,
    show_default=True,
    help="Number of days before a secret is considered stale.",
)
@click.option(
    "--fail-on-stale",
    is_flag=True,
    default=False,
    help="Exit with non-zero status if stale secrets are found.",
)
def audit_cmd(
    config_path: str,
    namespace_filter: str | None,
    stale_days: int,
    fail_on_stale: bool,
) -> None:
    """Audit secret freshness across configured Vault namespaces."""
    try:
        cfg = load_config(Path(config_path))
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(1)

    namespaces = [
        ns
        for ns in cfg.namespaces
        if namespace_filter is None or ns.name == namespace_filter
    ]

    if not namespaces:
        click.echo(
            f"No namespaces matched filter '{namespace_filter}'.", err=True
        )
        sys.exit(1)

    all_results: list = []

    for ns in namespaces:
        try:
            client = build_client(ns)
        except ClientError as exc:
            click.echo(f"[{ns.name}] Client error: {exc}", err=True)
            continue

        for path in ns.secret_paths:
            try:
                metadata = client.secrets.kv.v2.read_secret_metadata(
                    path=path, mount_point=ns.mount
                )
                all_results.append((ns, path, metadata))
            except Exception as exc:  # noqa: BLE001
                click.echo(f"[{ns.name}] Failed to read {path}: {exc}", err=True)

    report = AuditReport(results=all_results, stale_threshold_days=stale_days)
    _print_report(report)

    if fail_on_stale and stale_secrets(report):
        sys.exit(2)


def _print_report(report: AuditReport) -> None:
    summary = report.summary()
    click.echo(f"Total secrets audited : {summary['total']}")
    click.echo(f"Stale (>= threshold)  : {summary['stale']}")
    click.echo(f"Errors                : {summary['errors']}")

    stale = stale_secrets(report)
    if stale:
        click.echo("\nStale secrets:")
        for result in stale:
            click.echo(
                f"  [{result.namespace}] {result.path}  "
                f"last rotated: {result.last_rotated_at}"
            )
