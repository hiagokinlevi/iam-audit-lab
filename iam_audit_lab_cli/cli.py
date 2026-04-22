from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive import analyze_inactive_accounts
from analyzers.mfa import analyze_mfa_coverage
from analyzers.policy import analyze_aws_policy_document
from analyzers.privileges import analyze_excessive_permissions
from reports.markdown import generate_markdown_report
from schemas.findings import AuditFinding
from schemas.identity import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("collect-identities")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp", "entra"]), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def collect_identities(provider: str, output: Path) -> None:
    raise NotImplementedError("Provider collection wiring is implemented elsewhere in this project.")


@cli.command("analyze-privileges")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
def analyze_privileges(input_path: Path) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = analyze_excessive_permissions(records)
    for finding in findings:
        click.echo(f"[{finding.severity}] {finding.title} :: {finding.resource_id}")


@cli.command("analyze-policy")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
def analyze_policy(input_path: Path) -> None:
    findings = analyze_aws_policy_document(json.loads(input_path.read_text()))
    for finding in findings:
        click.echo(f"[{finding.severity}] {finding.title} :: {finding.resource_id}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON to stdout.")
def analyze_mfa(input_path: Path, as_json: bool) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = analyze_mfa_coverage(records)

    if as_json:
        click.echo(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
        return

    for finding in findings:
        click.echo(f"[{finding.severity}] {finding.title} :: {finding.resource_id}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--days", type=int, default=90, show_default=True)
def analyze_inactive(input_path: Path, days: int) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = analyze_inactive_accounts(records, inactivity_days=days)
    for finding in findings:
        click.echo(f"[{finding.severity}] {finding.title} :: {finding.resource_id}")


@cli.command("generate-report")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--findings", "findings_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
def generate_report(input_path: Path, findings_path: Path, output_path: Path) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = [AuditFinding.model_validate(item) for item in json.loads(findings_path.read_text())]
    output_path.write_text(generate_markdown_report(records, findings))


if __name__ == "__main__":
    cli()
