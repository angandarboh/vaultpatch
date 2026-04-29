"""CLI commands for capturing and restoring Vault snapshots."""
from __future__ import annotations

from pathlib import Path

import click

from vaultpatch.client import build_client
from vaultpatch.config import load_config
from vaultpatch.snapshot import capture_snapshot, load_snapshot, restore_snapshot, save_snapshot


@click.group()
def snapshot_cmd() -> None:
    """Capture or restore secret snapshots."""


@snapshot_cmd.command("capture")
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--namespace", required=True, help="Namespace name to snapshot.")
@click.option("--paths", required=True, multiple=True, help="Secret paths to capture.")
@click.option("--output", required=True, help="Destination file for the snapshot JSON.")
def capture_cmd(config_path: str, namespace: str, paths: tuple, output: str) -> None:
    """Capture current secret values to a local snapshot file."""
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        raise click.ClickException(str(exc))

    ns_cfg = next((n for n in cfg.namespaces if n.name == namespace), None)
    if ns_cfg is None:
        raise click.ClickException(f"Namespace '{namespace}' not found in config.")

    try:
        client = build_client(ns_cfg)
    except Exception as exc:
        raise click.ClickException(f"Client error: {exc}")

    snapshot = capture_snapshot(client, ns_cfg, list(paths))
    dest = Path(output)
    save_snapshot(snapshot, dest)
    click.echo(f"Snapshot saved to {dest} ({len(snapshot.entries)} entries).")


@snapshot_cmd.command("restore")
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--namespace", required=True, help="Namespace name to restore into.")
@click.option("--snapshot", "snapshot_path", required=True, help="Path to snapshot JSON.")
@click.option("--dry-run", is_flag=True, default=False, help="Print paths without writing.")
def restore_cmd(
    config_path: str, namespace: str, snapshot_path: str, dry_run: bool
) -> None:
    """Restore secrets from a snapshot file back into Vault."""
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        raise click.ClickException(str(exc))

    ns_cfg = next((n for n in cfg.namespaces if n.name == namespace), None)
    if ns_cfg is None:
        raise click.ClickException(f"Namespace '{namespace}' not found in config.")

    snapshot = load_snapshot(Path(snapshot_path))

    if dry_run:
        click.echo(f"[dry-run] Would restore {len(snapshot.entries)} paths:")
        for entry in snapshot.entries:
            click.echo(f"  {entry.path}")
        return

    try:
        client = build_client(ns_cfg)
    except Exception as exc:
        raise click.ClickException(f"Client error: {exc}")

    failed = restore_snapshot(client, ns_cfg, snapshot)
    if failed:
        click.echo(f"Restore completed with {len(failed)} failure(s):")
        for p in failed:
            click.echo(f"  FAILED: {p}")
    else:
        click.echo(f"Restored {len(snapshot.entries)} secrets successfully.")
