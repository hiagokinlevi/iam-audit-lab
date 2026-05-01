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
from schemas.findings import AuditFinding
from schemas.identity import IdentityRecord


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_identities(path: str) -> list[IdentityRecord]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [IdentityRecord.model_validate(item) for item in data]


def _write_findings(path: str, findings: list[AuditFinding]) -> None:
    serialized = [f.model_dump(mode="json") for f in findings]
    Path(path).write_text(json.dumps(serialized, indent=2), encoding="utf-8")


def _max_severity(findings: list[AuditFinding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 0)).severity.lower()


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def analyze_privileges_cmd(input_path: str, output_path: str) -> None:
    identities = _load_identities(input_path)
    findings = analyze_excessive_privileges(identities)
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option("--days", default=90, show_default=True, type=int, help="Inactive threshold in days.")
def analyze_inactive_cmd(input_path: str, output_path: str, days: int) -> None:
    identities = _load_identities(input_path)
    findings = analyze_inactive_accounts(identities, inactive_days=days)
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Return non-zero exit code if highest finding severity meets or exceeds this threshold.",
)
def analyze_mfa_cmd(input_path: str, output_path: str, fail_on_severity: str | None) -> None:
    identities = _load_identities(input_path)
    findings = analyze_mfa_coverage(identities)
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")

    if fail_on_severity:
      highest = _max_severity(findings)
      if highest and SEVERITY_ORDER.get(highest, 0) >= SEVERITY_ORDER[fail_on_severity.lower()]:
          raise click.ClickException(
              f"Failing due to finding severity threshold: highest={highest}, threshold={fail_on_severity.lower()}"
          )


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Return non-zero if any finding meets/exceeds severity threshold.",
)
def analyze_policy_cmd(input_path: str, output_path: str, fail_on_severity: str | None) -> None:
    policy_doc: dict[str, Any] = json.loads(Path(input_path).read_text(encoding="utf-8"))
    findings = analyze_aws_policy_document(policy_doc)
    _write_findings(output_path, findings)
    click.echo(f"Wrote {len(findings)} findings to {output_path}")

    if fail_on_severity:
        threshold = SEVERITY_ORDER[fail_on_severity.lower()]
        max_seen = 0
        for finding in findings:
            sev = SEVERITY_ORDER.get(finding.severity.lower(), 0)
            if sev > max_seen:
                max_seen = sev
        if max_seen >= threshold:
            raise click.ClickException(
                f"Severity threshold reached: highest={max_seen} threshold={threshold}"
            )


@cli.command("generate-report")
@click.option("--identities", "identities_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--findings", "findings_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def generate_report_cmd(identities_path: str, findings_path: str, output_path: str) -> None:
    identities = _load_identities(identities_path)
    findings_data = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    findings = [AuditFinding.model_validate(item) for item in findings_data]
    report = generate_markdown_report(identities, findings)
    Path(output_path).write_text(report, encoding="utf-8")
    click.echo(f"Wrote report to {output_path}")


if __name__ == "__main__":
    cli()
