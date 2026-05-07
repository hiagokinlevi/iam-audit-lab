import json
from pathlib import Path
from typing import Optional

import click

from analyzers.inactive import analyze_inactive_identities
from analyzers.mfa import analyze_mfa_coverage
from analyzers.privileges import analyze_excessive_privileges
from iam_audit_lab_cli.models import IdentityRecord
from providers.aws import collect_aws_identities
from providers.azure import collect_azure_identities
from providers.gcp import collect_gcp_identities


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("collect-identities")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Cloud provider to collect identities from.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False, writable=True),
    required=False,
    help="Write normalized identity records to this JSON file (defaults to stdout).",
)
def collect_identities(provider: str, output: Optional[Path]) -> None:
    """Collect and normalize identities from configured cloud providers.

    Use --output to persist results for downstream analyze-* commands in CI pipelines.
    """
    provider = provider.lower()
    records: list[IdentityRecord] = []

    if provider in {"aws", "all"}:
        records.extend(collect_aws_identities())
    if provider in {"azure", "all"}:
        records.extend(collect_azure_identities())
    if provider in {"gcp", "all"}:
        records.extend(collect_gcp_identities())

    payload = [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in records]

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        click.echo(f"Wrote {len(payload)} identity records to {output}")
    else:
        click.echo(json.dumps(payload, indent=2))


@cli.command("analyze-privileges")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
def analyze_privileges_cmd(input_path: Path) -> None:
    """Analyze identity records for excessive permissions."""
    data = json.loads(input_path.read_text(encoding="utf-8"))
    findings = analyze_excessive_privileges(data)
    click.echo(json.dumps([f.model_dump() if hasattr(f, "model_dump") else f.dict() for f in findings], indent=2))


@cli.command("analyze-mfa")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
def analyze_mfa_cmd(input_path: Path) -> None:
    """Analyze identity records for MFA coverage gaps."""
    data = json.loads(input_path.read_text(encoding="utf-8"))
    findings = analyze_mfa_coverage(data)
    click.echo(json.dumps([f.model_dump() if hasattr(f, "model_dump") else f.dict() for f in findings], indent=2))


@cli.command("analyze-inactive")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--days", type=int, default=90, show_default=True)
def analyze_inactive_cmd(input_path: Path, days: int) -> None:
    """Analyze identity records for inactive accounts."""
    data = json.loads(input_path.read_text(encoding="utf-8"))
    findings = analyze_inactive_identities(data, days_threshold=days)
    click.echo(json.dumps([f.model_dump() if hasattr(f, "model_dump") else f.dict() for f in findings], indent=2))


if __name__ == "__main__":
    cli()
