from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege_escalation import analyze_excessive_permissions
from reports.formatters import format_findings_as_markdown
from schemas.identity import IdentityRecord


def _load_identities(path: str) -> list[IdentityRecord]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [IdentityRecord.model_validate(item) for item in raw]


def _serialize_findings(findings: list[Any]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for finding in findings:
        if hasattr(finding, "model_dump"):
            serialized.append(finding.model_dump())
        elif isinstance(finding, dict):
            serialized.append(finding)
        else:
            serialized.append(vars(finding))
    return serialized


def _write_findings_output(output_path: str, findings: list[Any]) -> None:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    suffix = target.suffix.lower()
    if suffix == ".md":
        content = format_findings_as_markdown(findings)
        target.write_text(content, encoding="utf-8")
        return

    # Default to JSON for all other extensions (including .json)
    payload = _serialize_findings(findings)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
def analyze_privileges_cmd(input_path: str) -> None:
    identities = _load_identities(input_path)
    findings = analyze_excessive_permissions(identities)
    click.echo(json.dumps(_serialize_findings(findings), indent=2))


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
def analyze_mfa_cmd(input_path: str) -> None:
    identities = _load_identities(input_path)
    findings = analyze_mfa_coverage(identities)
    click.echo(json.dumps(_serialize_findings(findings), indent=2))


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--days", "days_inactive", default=90, show_default=True, type=int)
@click.option("--output", "output_path", required=False, type=click.Path())
def analyze_inactive_cmd(input_path: str, days_inactive: int, output_path: str | None) -> None:
    identities = _load_identities(input_path)
    findings = analyze_inactive_accounts(identities, days_inactive=days_inactive)
    click.echo(json.dumps(_serialize_findings(findings), indent=2))

    if output_path:
        _write_findings_output(output_path, findings)


if __name__ == "__main__":
    cli()
