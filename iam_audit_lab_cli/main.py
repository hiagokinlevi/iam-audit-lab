from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from analyzers.inactive import analyze_inactive_identities
from analyzers.mfa import analyze_mfa_coverage
from analyzers.policy import analyze_aws_policy_document
from analyzers.privileges import analyze_excessive_privileges
from reports.generator import generate_markdown_report
from schemas.findings import AuditFinding
from schemas.identity import IdentityRecord


ALLOWED_PROVIDERS = ("aws", "azure", "gcp", "entra")


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def analyze_privileges_cmd(input_path: str, output_path: str) -> None:
    """Analyze identities for excessive privileges."""
    records = _load_identity_records(Path(input_path))
    findings = analyze_excessive_privileges(records)
    _write_findings(Path(output_path), findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False), help="Path to collected identity JSON.")
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False), help="Path to write MFA analysis findings JSON.")
@click.option(
    "--provider",
    type=click.Choice(ALLOWED_PROVIDERS, case_sensitive=False),
    required=False,
    help="Optional provider filter (aws, azure, gcp, entra). Only matching identity records are analyzed.",
)
def analyze_mfa_cmd(input_path: str, output_path: str, provider: str | None) -> None:
    """Analyze identities for MFA coverage gaps."""
    records = _load_identity_records(Path(input_path))

    if provider:
        provider_normalized = provider.lower()
        records = [r for r in records if (r.provider or "").lower() == provider_normalized]

    findings = analyze_mfa_coverage(records)
    _write_findings(Path(output_path), findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option("--days", default=90, show_default=True, type=int)
def analyze_inactive_cmd(input_path: str, output_path: str, days: int) -> None:
    """Analyze identities for inactivity."""
    records = _load_identity_records(Path(input_path))
    findings = analyze_inactive_identities(records, inactivity_days=days)
    _write_findings(Path(output_path), findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def analyze_policy_cmd(input_path: str, output_path: str) -> None:
    """Analyze an exported AWS IAM policy document for risky patterns."""
    with Path(input_path).open("r", encoding="utf-8") as f:
        policy_doc = json.load(f)

    findings = analyze_aws_policy_document(policy_doc)
    _write_findings(Path(output_path), findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("generate-report")
@click.option("--identities", "identities_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--findings", "findings_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def generate_report_cmd(identities_path: str, findings_path: str, output_path: str) -> None:
    """Generate markdown report from identities and findings."""
    identities = _load_identity_records(Path(identities_path))
    findings = _load_findings(Path(findings_path))
    report = generate_markdown_report(identities, findings)
    Path(output_path).write_text(report, encoding="utf-8")
    click.echo(f"Wrote report to {output_path}")


def _load_identity_records(path: Path) -> list[IdentityRecord]:
    with path.open("r", encoding="utf-8") as f:
        raw: Any = json.load(f)
    return [IdentityRecord.model_validate(item) for item in raw]


def _load_findings(path: Path) -> list[AuditFinding]:
    with path.open("r", encoding="utf-8") as f:
        raw: Any = json.load(f)
    return [AuditFinding.model_validate(item) for item in raw]


def _write_findings(path: Path, findings: list[AuditFinding]) -> None:
    payload = [f.model_dump(mode="json") for f in findings]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    cli()
