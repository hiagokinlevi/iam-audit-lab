from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.offline_aws_policy import analyze_aws_policy_document
from analyzers.privilege_analysis import analyze_excessive_permissions
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
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp", "all"]), default="all")
@click.option("--output", type=click.Path(path_type=Path), required=True)
def collect_identities(provider: str, output: Path) -> None:
    records: list[IdentityRecord] = []

    if provider in ("aws", "all"):
        records.extend(collect_aws_identities())
    if provider in ("azure", "all"):
        records.extend(collect_azure_identities())
    if provider in ("gcp", "all"):
        records.extend(collect_gcp_identities())

    output.write_text(json.dumps([r.model_dump(mode="json") for r in records], indent=2), encoding="utf-8")
    click.echo(f"Collected {len(records)} identities -> {output}")


@cli.command("analyze-privileges")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def analyze_privileges_cmd(input_path: Path, output: Path) -> None:
    identities = [IdentityRecord.model_validate(i) for i in json.loads(input_path.read_text(encoding="utf-8"))]
    findings = analyze_excessive_permissions(identities)
    output.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
    click.echo(f"Generated {len(findings)} privilege findings -> {output}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def analyze_mfa_cmd(input_path: Path, output: Path) -> None:
    identities = [IdentityRecord.model_validate(i) for i in json.loads(input_path.read_text(encoding="utf-8"))]
    findings = analyze_mfa_coverage(identities)
    output.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
    click.echo(f"Generated {len(findings)} MFA findings -> {output}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--days", type=int, default=90, show_default=True)
def analyze_inactive_cmd(input_path: Path, output: Path, days: int) -> None:
    identities = [IdentityRecord.model_validate(i) for i in json.loads(input_path.read_text(encoding="utf-8"))]
    findings = analyze_inactive_accounts(identities, inactive_days=days)
    output.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
    click.echo(f"Generated {len(findings)} inactive-account findings -> {output}")


@cli.command("analyze-policy")
@click.option("--input", "input_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--fail-on-count", type=click.IntRange(min=0), required=False)
def analyze_policy_cmd(input_path: Path, output: Path, fail_on_count: int | None) -> None:
    policy_document = json.loads(input_path.read_text(encoding="utf-8"))
    findings = analyze_aws_policy_document(policy_document)
    output.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
    click.echo(f"Generated {len(findings)} policy findings -> {output}")

    if fail_on_count is not None and len(findings) >= fail_on_count:
        raise SystemExit(2)


@cli.command("generate-report")
@click.option("--identities", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--findings", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def generate_report_cmd(identities: Path, findings: Path, output: Path) -> None:
    identity_records = [IdentityRecord.model_validate(i) for i in json.loads(identities.read_text(encoding="utf-8"))]
    finding_records = [AuditFinding.model_validate(i) for i in json.loads(findings.read_text(encoding="utf-8"))]

    markdown = generate_markdown_report(identity_records, finding_records)
    output.write_text(markdown, encoding="utf-8")
    click.echo(f"Report written -> {output}")


if __name__ == "__main__":
    cli()
