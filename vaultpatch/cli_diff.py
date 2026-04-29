"""CLI sub-command: dry-run diff showing what a rotation would change."""

from __future__ import annotations

import sys
from typing import List

import click

from vaultpatch.client import build_client, ClientError
from vaultpatch.config import load_config, ConfigError
from vaultpatch.diff import build_diff, DiffReport
from vaultpatch.rotation import generate_secret


@click.command("diff")
@click.option("--config", "config_path", default="vaultpatch.yaml", show_default=True,
              help="Path to vaultpatch config file.")
@click.option("--namespace", "namespaces", multiple=True,
              help="Limit diff to specific namespace(s). Repeatable.")
@click.option("--mask", is_flag=True, default=True, show_default=True,
              help="Mask secret values in output.")
def diff_cmd(config_path: str, namespaces: List[str], mask: bool) -> None:
    """Show a dry-run diff of secrets that would be rotated."""
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"[error] Config: {exc}", err=True)
        sys.exit(1)

    targets = [
        ns for ns in cfg.namespaces
        if not namespaces or ns.name in namespaces
    ]

    if not targets:
        click.echo("No matching namespaces found.")
        sys.exit(0)

    report = DiffReport()

    for ns_cfg in targets:
        try:
            client = build_client(ns_cfg)
        except ClientError as exc:
            click.echo(f"[error] {ns_cfg.name}: {exc}", err=True)
            continue

        for path in ns_cfg.secret_paths:
            try:
                current_data = client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=ns_cfg.mount
                )["data"]["data"]
            except Exception:
                current_data = {}

            proposed = {key: generate_secret() for key in current_data} if current_data else {}
            diffs = build_diff(ns_cfg.name, path, proposed, current_data)
            if mask:
                diffs = [d.masked() for d in diffs]
            report.diffs.extend(diffs)

    _print_report(report)


def _print_report(report: DiffReport) -> None:
    if not report.diffs:
        click.echo("Nothing to diff.")
        return

    for diff in report.diffs:
        status = "NEW" if diff.is_new else ("CHANGED" if diff.changed else "UNCHANGED")
        click.echo(
            f"  [{status}] {diff.namespace}::{diff.path}#{diff.key}  "
            f"{diff.old_value!r} -> {diff.new_value!r}"
        )

    s = report.summary()
    click.echo(
        f"\nSummary: {s['total']} total | "
        f"{s['new']} new | {s['changed']} changed | {s['unchanged']} unchanged"
    )
