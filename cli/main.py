from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege_analysis import analyze_excessive_permissions
from providers.aws import collect_aws_identities
from providers.azure import collect_azure_identities
from providers.gcp import collect_gcp_identities
from reports.json_report import export_json_report
from reports.markdown_report import generate_markdown_report
from schemas.audit_finding import AuditFinding
from schemas.identity_record import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("collect-identities")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp", "all"]), default="all")
@click.option("--output", default="identities.json", show_default=True)
def collect_identities(provider: str, output: str) -> None:
    identities: list[IdentityRecord] = []

    if provider in ("aws", "all"):
        identities.extend(collect_aws_identities())
    if provider in ("azure", "all"):
        identities.extend(collect_azure_identities())
    if provider in ("gcp", "all"):
        identities.extend(collect_gcp_identities())

    Path(output).write_text(
        json.dumps([i.model_dump(mode="json") for i in identities], indent=2),
        encoding="utf-8",
    )
    click.echo(f"Collected {len(identities)} identities -> {output}")


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True)
@click.option("--output", default="findings.json", show_default=True)
def analyze_privileges_cmd(input_path: str, output: str) -> None:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    identities = [IdentityRecord(**row) for row in data]
    findings = analyze_excessive_permissions(identities)

    Path(output).write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2),
        encoding="utf-8",
    )
    click.echo(f"Generated {len(findings)} findings -> {output}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True)
@click.option("--output", default="mfa_findings.json", show_default=True)
def analyze_mfa_cmd(input_path: str, output: str) -> None:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    identities = [IdentityRecord(**row) for row in data]
    findings = analyze_mfa_coverage(identities)

    Path(output).write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2),
        encoding="utf-8",
    )
    click.echo(f"Generated {len(findings)} MFA findings -> {output}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True)
@click.option("--days", default=90, show_default=True, type=int)
@click.option("--output", default="inactive_findings.json", show_default=True)
def analyze_inactive_cmd(input_path: str, days: int, output: str) -> None:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    identities = [IdentityRecord(**row) for row in data]
    findings = analyze_inactive_accounts(identities, inactive_days=days)

    Path(output).write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2),
        encoding="utf-8",
    )
    click.echo(f"Generated {len(findings)} inactive-account findings -> {output}")


@cli.command("generate-report")
@click.option("--identities", "identities_path", required=True)
@click.option("--findings", "findings_path", required=True)
@click.option("--format", "report_format", type=click.Choice(["markdown", "json"]), default="markdown", show_default=True)
@click.option("--output", default=None)
def generate_report_cmd(identities_path: str, findings_path: str, report_format: str, output: str | None) -> None:
    identities_raw = json.loads(Path(identities_path).read_text(encoding="utf-8"))
    findings_raw = json.loads(Path(findings_path).read_text(encoding="utf-8"))

    identities = [IdentityRecord(**row) for row in identities_raw]
    findings = [AuditFinding(**row) for row in findings_raw]

    if report_format == "json":
        out = output or "iam_audit_report.json"
        export_json_report(findings=findings, identities=identities, output_path=out)
    else:
        out = output or "iam_audit_report.md"
        markdown = generate_markdown_report(findings=findings, identities=identities)
        Path(out).write_text(markdown, encoding="utf-8")

    click.echo(f"Report written -> {out}")


if __name__ == "__main__":
    cli()
