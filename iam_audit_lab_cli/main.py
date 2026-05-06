from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive import analyze_inactive_accounts
from analyzers.mfa import analyze_mfa_coverage
from analyzers.policy import analyze_aws_policy_document
from analyzers.privileges import analyze_excessive_permissions
from reports.generator import generate_report
from schemas.models import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=False, type=click.Path(path_type=Path))
def analyze_privileges_cmd(input_path: Path, output_path: Path | None) -> None:
    identities = _load_identities(input_path)
    findings = analyze_excessive_permissions(identities)

    payload = [finding.model_dump(mode="json") for finding in findings]
    if output_path:
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        click.echo(f"Wrote {len(payload)} findings to {output_path}")
    else:
        click.echo(json.dumps(payload, indent=2))


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
def analyze_mfa_cmd(input_path: Path, output_format: str) -> None:
    identities = _load_identities(input_path)
    result = analyze_mfa_coverage(identities)

    if output_format == "json":
        click.echo(json.dumps(result, indent=2))
        return

    click.echo("MFA Coverage Summary")
    click.echo("--------------------")
    click.echo(f"Total identities:       {result['total_identities']}")
    click.echo(f"MFA enabled:            {result['mfa_enabled']}")
    click.echo(f"MFA missing:            {result['mfa_missing']}")
    click.echo(f"Coverage (%):           {result['coverage_percent']}")

    privileged_missing = result.get("privileged_without_mfa", [])
    if privileged_missing:
        click.echo("\nPrivileged identities without MFA")
        click.echo("---------------------------------")
        for item in privileged_missing:
            click.echo(f"- {item.get('provider', 'unknown')}:{item.get('name', 'unknown')}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--days", default=90, show_default=True, type=int)
def analyze_inactive_cmd(input_path: Path, days: int) -> None:
    identities = _load_identities(input_path)
    findings = analyze_inactive_accounts(identities, days_threshold=days)
    click.echo(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--fail-on-severity", type=click.Choice(["low", "medium", "high", "critical"]), default=None)
def analyze_policy_cmd(input_path: Path, fail_on_severity: str | None) -> None:
    policy_doc = json.loads(input_path.read_text(encoding="utf-8"))
    findings = analyze_aws_policy_document(policy_doc)

    payload = [f.model_dump(mode="json") for f in findings]
    click.echo(json.dumps(payload, indent=2))

    if fail_on_severity:
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order[fail_on_severity]
        if any(order.get(f.severity, 0) >= threshold for f in findings):
            raise SystemExit(2)


@cli.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
def generate_report_cmd(input_path: Path, output_path: Path) -> None:
    identities = _load_identities(input_path)
    report = generate_report(identities)
    output_path.write_text(report, encoding="utf-8")
    click.echo(f"Report written to {output_path}")


def _load_identities(path: Path) -> list[IdentityRecord]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [IdentityRecord.model_validate(item) for item in raw]


if __name__ == "__main__":
    cli()
