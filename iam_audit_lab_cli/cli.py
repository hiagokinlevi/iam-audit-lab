from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from iam_audit_lab_cli.collectors import collect_identities


@click.group()
def cli() -> None:
    """iam-audit-lab command line interface."""


@cli.command("collect-identities")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp", "all"]), default="all", show_default=True)
@click.option("--json", "json_output", is_flag=True, help="Emit normalized IdentityRecord data as JSON.")
@click.option("--out", "out_file", type=click.Path(path_type=Path), default=None, help="Write output to file path.")
def collect_identities_cmd(provider: str, json_output: bool, out_file: Path | None) -> None:
    """Collect identities from configured providers."""
    records = collect_identities(provider=provider)

    if json_output:
        normalized: list[dict[str, Any]] = [r.model_dump(mode="json") if hasattr(r, "model_dump") else dict(r) for r in records]
        normalized = sorted(
            normalized,
            key=lambda r: (
                str(r.get("provider", "")),
                str(r.get("identity_type", "")),
                str(r.get("account_id", "")),
                str(r.get("principal_name", "")),
                str(r.get("id", "")),
            ),
        )
        payload = json.dumps(normalized, indent=2)
        if out_file:
            out_file.write_text(payload + "\n", encoding="utf-8")
            click.echo(f"Wrote {len(normalized)} identities to {out_file}")
            return
        click.echo(payload)
        return

    click.echo(f"Collected {len(records)} identities")
