"""CLI command for bulk secret rotation across Vault namespaces."""
from __future__ import annotations

import sys
from collections import defaultdict
from typing import Dict, List

import click
import hvac

from .client import build_client, ClientError
from .config import load_config, ConfigError, NamespaceConfig
from .rotation import rotate_secret, RotationReport, RotationResult


def _group_by_namespace(
    paths: List[str], namespaces: List[NamespaceConfig]
) -> Dict[str, List[str]]:
    """Return {namespace_name: [paths]} for namespaces whose path_prefix matches."""
    grouped: Dict[str, List[str]] = defaultdict(list)
    for ns in namespaces:
        for path in paths:
            if path.startswith(ns.path_prefix):
                grouped[ns.name].append(path)
    return dict(grouped)


@click.command("rotate")
@click.option("--config", "config_path", required=True, help="Path to vaultpatch config YAML.")
@click.option("--namespace", "ns_filter", default=None, help="Limit rotation to a single namespace.")
@click.option("--path", "paths", multiple=True, required=True, help="Secret path(s) to rotate.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview rotations without writing.")
@click.option("--length", default=32, show_default=True, help="Generated secret length.")
def rotate_cmd(
    config_path: str,
    ns_filter: str | None,
    paths: tuple,
    dry_run: bool,
    length: int,
) -> None:
    """Bulk-rotate secrets at the given paths across configured namespaces."""
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(1)

    namespaces = cfg.namespaces
    if ns_filter:
        namespaces = [ns for ns in namespaces if ns.name == ns_filter]
        if not namespaces:
            click.echo(f"No namespace matching '{ns_filter}' found.", err=True)
            sys.exit(1)

    path_list = list(paths)
    grouped = _group_by_namespace(path_list, namespaces)

    all_results: list[RotationResult] = []

    for ns in namespaces:
        ns_paths = grouped.get(ns.name, [])
        if not ns_paths:
            continue
        try:
            client = build_client(ns)
        except ClientError as exc:
            click.echo(f"[{ns.name}] Client error: {exc}", err=True)
            continue

        for path in ns_paths:
            if dry_run:
                click.echo(f"[DRY-RUN] [{ns.name}] Would rotate: {path}")
                continue
            result = rotate_secret(client, ns, path, length=length)
            all_results.append(result)
            status = "OK" if not result.error else f"FAIL ({result.error})"
            click.echo(f"[{ns.name}] {path}: {status}")

    if dry_run:
        return

    report = RotationReport(all_results)
    click.echo(f"\nSummary: {len(report.successes())} rotated, {len(report.failed())} failed.")
    if report.failed():
        sys.exit(2)
