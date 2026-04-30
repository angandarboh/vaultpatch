"""CLI command for rolling back secrets to a previous snapshot."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from vaultpatch.client import build_client, ClientError
from vaultpatch.config import load_config, ConfigError
from vaultpatch.rollback import perform_rollback, RollbackReport
from vaultpatch.snapshot import load_snapshot


def _print_report(report: RollbackReport) -> None:
    summary = report.summary()
    click.echo(f"\nRollback complete: {summary['successes']} succeeded, {summary['failures']} failed.")

    if report.successes():
        click.echo("\n✔ Restored:")
        for r in report.successes():
            click.echo(f"  [{r.namespace}] {r.path}")

    if report.failed():
        click.echo("\n✘ Failed:")
        for r in report.failed():
            click.echo(f"  [{r.namespace}] {r.path} — {r.error}")


@click.command(name="rollback")
@click.option(
    "--config", "config_path",
    default="vaultpatch.yaml",
    show_default=True,
    help="Path to the vaultpatch config file.",
)
@click.option(
    "--snapshot", "snapshot_path",
    required=True,
    help="Path to the snapshot JSON file to restore from.",
)
@click.option(
    "--namespace", "namespace_filter",
    default=None,
    help="Restrict rollback to a specific namespace alias.",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="Preview which secrets would be restored without writing.",
)
def rollback_cmd(
    config_path: str,
    snapshot_path: str,
    namespace_filter: str | None,
    dry_run: bool,
) -> None:
    """Restore secrets from a snapshot file."""
    try:
        cfg = load_config(Path(config_path))
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(1)

    snapshot_file = Path(snapshot_path)
    if not snapshot_file.exists():
        click.echo(f"Snapshot file not found: {snapshot_path}", err=True)
        sys.exit(1)

    snapshot = load_snapshot(snapshot_file)

    namespaces = cfg.namespaces
    if namespace_filter:
        namespaces = [ns for ns in namespaces if ns.alias == namespace_filter]
        if not namespaces:
            click.echo(f"No namespace matching alias '{namespace_filter}'.", err=True)
            sys.exit(1)

    if dry_run:
        click.echo("[dry-run] The following secrets would be restored:")
        for entry in snapshot.entries:
            if namespace_filter and entry.namespace != namespace_filter:
                continue
            click.echo(f"  [{entry.namespace}] {entry.path}")
        return

    all_results: list = []
    for ns_cfg in namespaces:
        try:
            client = build_client(ns_cfg)
        except ClientError as exc:
            click.echo(f"Client error for '{ns_cfg.alias}': {exc}", err=True)
            continue

        report = perform_rollback(ns_cfg, client, snapshot)
        all_results.extend(report.results)

    from vaultpatch.rollback import RollbackReport  # local to avoid circular
    combined = RollbackReport(results=all_results)
    _print_report(combined)

    if combined.failed():
        sys.exit(2)
