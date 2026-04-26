from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege import analyze_excessive_permissions
from analyzers.aws_policy import analyze_aws_policy_document
from reports.generator import generate_markdown_report
from schemas.identity import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def analyze_privileges_cmd(input_path: Path, output_path: Path) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = analyze_excessive_permissions(records)
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
@click.option("--inactive-days", default=90, show_default=True, type=int, help="Inactivity threshold in days.")
@click.option(
    "--fail-on-findings",
    type=int,
    default=None,
    help="Exit with code 2 when inactive-account findings are greater than or equal to this value.",
)
def analyze_inactive_cmd(
    input_path: Path,
    output_path: Path,
    inactive_days: int,
    fail_on_findings: int | None,
) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = analyze_inactive_accounts(records, inactive_days=inactive_days)
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    click.echo(f"Wrote {len(findings)} findings to {output_path}")

    if fail_on_findings is not None and len(findings) >= fail_on_findings:
        raise click.exceptions.Exit(2)


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def analyze_mfa_cmd(input_path: Path, output_path: Path) -> None:
    records = [IdentityRecord.model_validate(item) for item in json.loads(input_path.read_text())]
    findings = analyze_mfa_coverage(records)
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Exit with code 2 if any finding is at or above this severity.",
)
def analyze_policy_cmd(input_path: Path, output_path: Path, fail_on_severity: str | None) -> None:
    document = json.loads(input_path.read_text())
    findings = analyze_aws_policy_document(document)
    output_path.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    click.echo(f"Wrote {len(findings)} findings to {output_path}")

    if fail_on_severity:
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = order[fail_on_severity.upper()]
        if any(order.get(f.severity.upper(), 0) >= threshold for f in findings):
            raise click.exceptions.Exit(2)


@cli.command("generate-report")
@click.option("--identities", "identities_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--findings", "findings_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def generate_report_cmd(identities_path: Path, findings_path: Path, output_path: Path) -> None:
    identities = [IdentityRecord.model_validate(item) for item in json.loads(identities_path.read_text())]
    findings = json.loads(findings_path.read_text())
    report = generate_markdown_report(identities, findings)
    output_path.write_text(report)
    click.echo(f"Wrote report to {output_path}")


if __name__ == "__main__":
    cli()
