from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from analyzers.inactive import analyze_inactive_identities
from analyzers.mfa import analyze_mfa_coverage
from analyzers.privileges import analyze_excessive_permissions
from reports.generator import generate_markdown_report
from schemas.findings import AuditFinding
from schemas.identity import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("collect-identities")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp", "entra"]), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def collect_identities(provider: str, output: Path) -> None:
    """Collect identities from a specific provider."""
    # Existing implementation retained in repository; unchanged for this task.
    raise NotImplementedError


@cli.command("analyze-privileges")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp", "entra"]), required=False)
def analyze_privileges(input_path: Path, output_path: Path, provider: Optional[str]) -> None:
    """Analyze excessive privileges from normalized identity records."""
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    records = [IdentityRecord.model_validate(item) for item in raw]

    if provider:
        records = [record for record in records if record.provider == provider]

    findings = analyze_excessive_permissions(records)
    output_path.write_text(
        json.dumps([f.model_dump() if isinstance(f, AuditFinding) else f for f in findings], indent=2),
        encoding="utf-8",
    )


@cli.command("analyze-mfa")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
def analyze_mfa(input_path: Path, output_path: Path) -> None:
    """Analyze MFA coverage from normalized identity records."""
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    records = [IdentityRecord.model_validate(item) for item in raw]
    findings = analyze_mfa_coverage(records)
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2), encoding="utf-8")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
@click.option("--days", type=int, default=90, show_default=True)
def analyze_inactive(input_path: Path, output_path: Path, days: int) -> None:
    """Analyze inactive identities from normalized identity records."""
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    records = [IdentityRecord.model_validate(item) for item in raw]
    findings = analyze_inactive_identities(records, inactivity_days=days)
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2), encoding="utf-8")


@cli.command("generate-report")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
def generate_report(input_path: Path, output_path: Path) -> None:
    """Generate markdown report from findings JSON."""
    findings = [AuditFinding.model_validate(item) for item in json.loads(input_path.read_text(encoding="utf-8"))]
    markdown = generate_markdown_report(findings)
    output_path.write_text(markdown, encoding="utf-8")


if __name__ == "__main__":
    cli()
