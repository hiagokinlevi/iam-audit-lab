import json
from pathlib import Path

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege_analyzer import analyze_excessive_permissions
from reports.markdown_report import generate_markdown_report
from schemas.models import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
def analyze_privileges_cmd(input_path: Path) -> None:
    records = [IdentityRecord.model_validate(x) for x in json.loads(input_path.read_text())]
    findings = analyze_excessive_permissions(records)

    if not findings:
        click.echo("No excessive privilege findings.")
        return

    click.echo(f"Found {len(findings)} excessive privilege finding(s):")
    for f in findings:
        click.echo(f"- [{f.severity}] {f.provider}:{f.identity_id} -> {f.issue}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
def analyze_mfa_cmd(input_path: Path) -> None:
    records = [IdentityRecord.model_validate(x) for x in json.loads(input_path.read_text())]
    result = analyze_mfa_coverage(records)

    click.echo("MFA Coverage")
    click.echo("------------")
    click.echo(f"Total identities: {result.total_identities}")
    click.echo(f"MFA enabled: {result.mfa_enabled}")
    click.echo(f"MFA missing: {result.mfa_missing}")
    click.echo(f"Coverage: {result.coverage_percent:.2f}%")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--days", "days_threshold", default=90, show_default=True, type=int)
@click.option("--json", "json_output", is_flag=True, help="Emit findings as JSON to stdout")
def analyze_inactive_cmd(input_path: Path, days_threshold: int, json_output: bool) -> None:
    records = [IdentityRecord.model_validate(x) for x in json.loads(input_path.read_text())]
    findings = analyze_inactive_accounts(records, days_threshold=days_threshold)

    if json_output:
        click.echo(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
        return

    if not findings:
        click.echo(f"No inactive accounts older than {days_threshold} days.")
        return

    click.echo(f"Found {len(findings)} inactive account(s):")
    for f in findings:
        click.echo(
            f"- [{f.severity}] {f.provider}:{f.identity_id} -> {f.issue} (inactive_days={f.inactive_days})"
        )


@cli.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def generate_report_cmd(input_path: Path, output_path: Path) -> None:
    records = [IdentityRecord.model_validate(x) for x in json.loads(input_path.read_text())]
    report = generate_markdown_report(records)
    output_path.write_text(report)
    click.echo(f"Report written to {output_path}")


if __name__ == "__main__":
    cli()
