"""CLI command for bulk-rotating secrets across Vault namespaces."""
from __future__ import annotations

import sys
from collections import defaultdict
from typing import Dict, List

import click

from vaultpatch.client import build_client, ClientError
from vaultpatch.config import load_config, ConfigError, NamespaceConfig
from vaultpatch.rotation import rotate_secret, RotationReport


def _group_by_namespace(
    configs: List[NamespaceConfig],
) -> Dict[str, List[NamespaceConfig]]:
    """Group namespace configs by their Vault address."""
    groups: Dict[str, List[NamespaceConfig]] = defaultdict(list)
    for cfg in configs:
        groups[cfg.url].append(cfg)
    return dict(groups)


@click.command("rotate")
@click.option(
    "--config", "config_path", required=True, help="Path to vaultpatch config YAML."
)
@click.option(
    "--namespace", "namespace_filter", default=None, help="Limit rotation to one namespace name."
)
@click.option(
    "--dry-run", is_flag=True, default=False, help="Preview rotations without writing to Vault."
)
def rotate_cmd(config_path: str, namespace_filter: str | None, dry_run: bool) -> None:
    """Bulk-rotate secrets defined in the config file."""
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

    if dry_run:
        click.echo("[dry-run] No changes will be written to Vault.")

    all_reports: list[RotationReport] = []

    for ns in namespaces:
        click.echo(f"\nNamespace: {ns.name} ({ns.url})")
        try:
            client = build_client(ns)
        except ClientError as exc:
            click.echo(f"  [ERROR] Could not build client: {exc}", err=True)
            continue

        for path in ns.secret_paths:
            report = rotate_secret(client, ns, path, dry_run=dry_run)
            all_reports.append(report)
            status = "OK" if report.success else "FAIL"
            tag = "[dry-run] " if dry_run else ""
            click.echo(f"  {tag}[{status}] {path}" + (f" — {report.error}" if report.error else ""))

    total = len(all_reports)
    succeeded = sum(1 for r in all_reports if r.success)
    failed = total - succeeded
    click.echo(f"\nSummary: {succeeded}/{total} rotated, {failed} failed.")
    if failed:
        sys.exit(2)
