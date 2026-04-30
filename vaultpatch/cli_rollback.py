"""CLI command: vaultpatch rollback — restore secrets from a snapshot file."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from vaultpatch.client import build_client, ClientError
from vaultpatch.config import load_config, ConfigError
from vaultpatch.rollback import rollback_snapshot
from vaultpatch.snapshot import Snapshot


@click.command("rollback")
@click.argument("snapshot_file", type=click.Path(exists=True))
@click.option("--config", "config_path", default="vaultpatch.yaml", show_default=True)
@click.option("--namespace", "ns_filter", default=None, help="Limit to one namespace.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without writing.")
def rollback_cmd(
    snapshot_file: str,
    config_path: str,
    ns_filter: str | None,
    dry_run: bool,
) -> None:
    """Restore secrets from SNAPSHOT_FILE to Vault."""
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(1)

    raw = json.loads(Path(snapshot_file).read_text())
    snapshot = Snapshot.from_dict(raw)

    namespaces = [
        ns for ns in cfg.namespaces
        if ns_filter is None or ns.name == ns_filter
    ]

    if not namespaces:
        click.echo("No matching namespaces found.", err=True)
        sys.exit(1)

    if dry_run:
        click.echo("[dry-run] No changes will be written.")

    exit_code = 0
    for ns in namespaces:
        click.echo(f"\nNamespace: {ns.name}")
        try:
            client = build_client(ns)
        except ClientError as exc:
            click.echo(f"  Auth error: {exc}", err=True)
            exit_code = 1
            continue

        report = rollback_snapshot(client, snapshot, ns.name, dry_run=dry_run)

        for result in report.successes():
            marker = "(dry-run) " if dry_run else ""
            click.echo(f"  {marker}restored  {result.path}")
        for result in report.failed():
            click.echo(f"  FAILED    {result.path}: {result.error}", err=True)
            exit_code = 1

        click.echo(f"  {report.summary()}")

    sys.exit(exit_code)
