"""CLI sub-command: rotate secrets across namespaces."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from vaultpatch.client import ClientError, build_client
from vaultpatch.config import ConfigError, load_config
from vaultpatch.rotation import rotate_namespace


@click.command("rotate")
@click.option(
    "--config",
    "config_path",
    default="vaultpatch.yaml",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to vaultpatch config file.",
)
@click.option(
    "--targets",
    "targets_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="JSON file listing {namespace, path, key} rotation targets.",
)
@click.option("--dry-run", is_flag=True, default=False, help="Print plan without rotating.")
def rotate_cmd(config_path: str, targets_path: str, dry_run: bool) -> None:
    """Bulk-rotate secrets defined in TARGETS across configured namespaces."""
    try:
        cfg = load_config(Path(config_path))
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(1)

    raw: list[dict[str, Any]] = json.loads(Path(targets_path).read_text())
    ns_map = {ns.name: ns for ns in cfg.namespaces}

    for ns_name, targets in _group_by_namespace(raw).items():
        ns_config = ns_map.get(ns_name)
        if ns_config is None:
            click.echo(f"[WARN] Unknown namespace '{ns_name}', skipping.", err=True)
            continue

        if dry_run:
            for t in targets:
                click.echo(f"[DRY-RUN] {ns_name} :: {t['path']}#{t['key']}")
            continue

        try:
            client = build_client(ns_config)
        except ClientError as exc:
            click.echo(f"[ERROR] {ns_name}: {exc}", err=True)
            continue

        report = rotate_namespace(client, ns_config, targets)
        for result in report.results:
            status = "OK" if result.success else f"FAIL({result.error})"
            click.echo(f"[{status}] {ns_name} :: {result.path}#{result.key}")

        summary = report.summary()
        click.echo(
            f"  → namespace '{ns_name}': "
            f"{summary['succeeded']}/{summary['total']} rotated."
        )


def _group_by_namespace(
    targets: list[dict[str, Any]]
) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for t in targets:
        grouped.setdefault(t["namespace"], []).append(
            {"path": t["path"], "key": t["key"]}
        )
    return grouped
