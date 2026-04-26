from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import click

from analyzers.inactive import analyze_inactive_identities
from analyzers.mfa import analyze_mfa_coverage
from analyzers.privileges import analyze_excessive_privileges
from providers.aws import collect_aws_identities
from providers.azure import collect_azure_identities
from providers.gcp import collect_gcp_identities
from reports.generator import generate_markdown_report
from schemas.finding import AuditFinding
from schemas.identity import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("collect-identities")
@click.option("--aws-profile", default=None, help="AWS profile name to use.")
@click.option("--azure-tenant-id", default=None, help="Azure tenant ID override.")
@click.option("--gcp-project", default=None, help="GCP project ID.")
@click.option(
    "--provider",
    "providers",
    multiple=True,
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    help="Provider(s) to collect from. Repeat to include multiple (e.g., --provider aws --provider gcp). Defaults to all.",
)
@click.option("--output", required=True, type=click.Path(path_type=Path), help="Output JSON path.")
def collect_identities_cmd(
    aws_profile: str | None,
    azure_tenant_id: str | None,
    gcp_project: str | None,
    providers: tuple[str, ...],
    output: Path,
) -> None:
    """Collect identities from cloud providers and write normalized JSON records."""
    selected = {p.lower() for p in providers} if providers else {"aws", "azure", "gcp"}

    records: list[IdentityRecord] = []

    if "aws" in selected:
      records.extend(collect_aws_identities(profile=aws_profile))
    if "azure" in selected:
      records.extend(collect_azure_identities(tenant_id=azure_tenant_id))
    if "gcp" in selected:
      records.extend(collect_gcp_identities(project_id=gcp_project))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps([r.model_dump(mode="json") for r in records], indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(records)} identity records to {output}")


def _load_identities(path: Path) -> list[IdentityRecord]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [IdentityRecord.model_validate(item) for item in raw]


def _write_findings(path: Path, findings: Iterable[AuditFinding]) -> None:
    data = [f.model_dump(mode="json") for f in findings]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def analyze_privileges_cmd(input_path: Path, output_path: Path) -> None:
    """Analyze collected identities for excessive privileges."""
    findings = analyze_excessive_privileges(_load_identities(input_path))
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} privilege findings to {output_path}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def analyze_mfa_cmd(input_path: Path, output_path: Path) -> None:
    """Analyze MFA coverage for collected identities."""
    findings = analyze_mfa_coverage(_load_identities(input_path))
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} MFA findings to {output_path}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
@click.option("--days", default=90, show_default=True, type=int)
def analyze_inactive_cmd(input_path: Path, output_path: Path, days: int) -> None:
    """Analyze collected identities for inactivity over threshold days."""
    findings = analyze_inactive_identities(_load_identities(input_path), days=days)
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} inactivity findings to {output_path}")


@cli.command("generate-report")
@click.option("--identities", "identities_path", required=True, type=click.Path(path_type=Path))
@click.option("--findings", "findings_path", required=True, type=click.Path(path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def generate_report_cmd(identities_path: Path, findings_path: Path, output_path: Path) -> None:
    """Generate markdown report from identities and findings JSON files."""
    identities = _load_identities(identities_path)
    findings_raw = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = [AuditFinding.model_validate(item) for item in findings_raw]
    markdown = generate_markdown_report(identities, findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    click.echo(f"Wrote report to {output_path}")


if __name__ == "__main__":
    cli()
