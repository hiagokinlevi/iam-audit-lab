from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from analyzers.inactive import analyze_inactive_identities
from schemas.identity import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to collected identities JSON file.")
@click.option("--days", "inactive_days", default=90, show_default=True, type=int, help="Inactive threshold in days.")
@click.option(
    "--min-last-seen-days",
    type=int,
    default=None,
    help=(
        "Optional minimum age (days since last seen) required to emit a finding. "
        "When unset, behavior remains unchanged."
    ),
)
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path), help="Path to write inactive findings JSON.")
def analyze_inactive_command(
    input_path: Path,
    inactive_days: int,
    min_last_seen_days: Optional[int],
    output_path: Path,
) -> None:
    """Analyze identities for inactivity risk."""
    data = json.loads(input_path.read_text(encoding="utf-8"))
    identities = [IdentityRecord.model_validate(item) for item in data]

    findings = analyze_inactive_identities(
        identities=identities,
        inactive_days=inactive_days,
        min_last_seen_days=min_last_seen_days,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2),
        encoding="utf-8",
    )

    click.echo(f"Wrote {len(findings)} inactive findings to {output_path}")


if __name__ == "__main__":
    cli()
