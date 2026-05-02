from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from schemas.identity_record import IdentityRecord


@click.group()
def cli() -> None:
    pass


def _load_identities(path: Path) -> list[IdentityRecord]:
    raw = json.loads(path.read_text())
    return [IdentityRecord.model_validate(item) for item in raw]


@cli.command("analyze-inactive")
@click.option("--input", "input_path", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
@click.option("--days", "days_threshold", type=int, default=90, show_default=True)
@click.option(
    "--provider",
    "provider",
    type=click.Choice(["aws", "azure", "gcp", "entra"], case_sensitive=False),
    required=False,
    help="Only analyze identities from a specific provider.",
)
def analyze_inactive_command(
    input_path: Path,
    output_path: Path,
    days_threshold: int,
    provider: Optional[str],
) -> None:
    identities = _load_identities(input_path)

    if provider:
        selected = provider.lower()
        identities = [i for i in identities if (i.provider or "").lower() == selected]

    findings = analyze_inactive_accounts(identities, inactive_days=days_threshold)
    output_path.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))


if __name__ == "__main__":
    cli()
