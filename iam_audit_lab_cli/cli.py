from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from analyzers.inactive import analyze_inactive_accounts
from analyzers.mfa import analyze_mfa_coverage
from analyzers.policy import analyze_aws_policy_document
from analyzers.privileges import analyze_excessive_privileges
from reports.generator import generate_markdown_report
from schemas.models import IdentityRecord


def _load_identities(path: str) -> list[IdentityRecord]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise click.ClickException("Input must be a JSON array of identity records")
    return [IdentityRecord.model_validate(item) for item in raw]


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "model_dump"):
        data = finding.model_dump()
    elif isinstance(finding, dict):
        data = dict(finding)
    else:
        data = {
            "severity": getattr(finding, "severity", "unknown"),
            "finding_type": getattr(finding, "finding_type", "unknown"),
            "principal_id": getattr(finding, "principal_id", None),
            "account_id": getattr(finding, "account_id", None),
            "risk_metadata": getattr(finding, "risk_metadata", {}),
            "message": getattr(finding, "message", str(finding)),
        }

    # Normalize expected fields for JSON consumers.
    data.setdefault("severity", "unknown")
    data.setdefault("finding_type", "unknown")
    data.setdefault("principal_id", data.get("principal") or data.get("principal_name"))
    data.setdefault("account_id", data.get("account") or data.get("subscription_id") or data.get("project_id"))
    data.setdefault("risk_metadata", {})
    return data


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=False, type=click.Path(dir_okay=False))
@click.option("--json", "json_output", is_flag=True, help="Emit structured JSON findings instead of human-readable output")
def analyze_privileges_cmd(input_path: str, output_path: str | None, json_output: bool) -> None:
    identities = _load_identities(input_path)
    findings = analyze_excessive_privileges(identities)

    if json_output:
        payload = {
            "finding_count": len(findings),
            "findings": [_finding_to_dict(f) for f in findings],
        }
        rendered = json.dumps(payload, indent=2)
        if output_path:
            Path(output_path).write_text(rendered + "\n", encoding="utf-8")
        else:
            click.echo(rendered)
        return

    if not findings:
        click.echo("No excessive privilege findings detected.")
        return

    lines: list[str] = [f"Detected {len(findings)} excessive privilege finding(s):"]
    for idx, finding in enumerate(findings, start=1):
        sev = getattr(finding, "severity", "unknown")
        ftype = getattr(finding, "finding_type", "unknown")
        principal = getattr(finding, "principal_id", None) or getattr(finding, "principal", "unknown")
        account = getattr(finding, "account_id", None) or getattr(finding, "account", "unknown")
        msg = getattr(finding, "message", "")
        lines.append(f"{idx}. [{sev}] {ftype} principal={principal} account={account} {msg}".strip())

    report = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(report + "\n", encoding="utf-8")
    else:
        click.echo(report)


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
def analyze_policy_cmd(input_path: str) -> None:
    findings = analyze_aws_policy_document(Path(input_path).read_text(encoding="utf-8"))
    if findings:
        click.echo(json.dumps([f.model_dump() if hasattr(f, "model_dump") else f for f in findings], indent=2))
        raise SystemExit(2)
    click.echo("No policy escalation findings detected.")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
def analyze_mfa_cmd(input_path: str) -> None:
    identities = _load_identities(input_path)
    result = analyze_mfa_coverage(identities)
    click.echo(json.dumps(result, indent=2))


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--days", default=90, show_default=True, type=int)
def analyze_inactive_cmd(input_path: str, days: int) -> None:
    identities = _load_identities(input_path)
    findings = analyze_inactive_accounts(identities, days_threshold=days)
    click.echo(json.dumps([f.model_dump() if hasattr(f, "model_dump") else f for f in findings], indent=2))


@cli.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def generate_report_cmd(input_path: str, output_path: str) -> None:
    identities = _load_identities(input_path)
    report = generate_markdown_report(identities)
    Path(output_path).write_text(report, encoding="utf-8")
    click.echo(f"Report written to {output_path}")


if __name__ == "__main__":
    cli()
