from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege_analyzer import analyze_privileges
from analyzers.aws_policy_analyzer import analyze_aws_policy


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_meets_or_exceeds(finding_severity: str, threshold: str) -> bool:
    finding_value = SEVERITY_ORDER.get(str(finding_severity).lower(), 0)
    threshold_value = SEVERITY_ORDER.get(str(threshold).lower(), 999)
    return finding_value >= threshold_value


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Return non-zero if any finding is at or above this severity.",
)
def analyze_privileges_cmd(input_path: Path, output_path: Path, fail_on_severity: str | None) -> None:
    """Analyze identity privileges and emit findings."""
    with input_path.open("r", encoding="utf-8") as f:
        identities = json.load(f)

    findings = analyze_privileges(identities)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    if fail_on_severity:
        should_fail = any(
            _severity_meets_or_exceeds(f.get("severity", ""), fail_on_severity)
            for f in findings
        )
        if should_fail:
            raise click.ClickException(
                f"Found findings with severity >= {fail_on_severity}."
            )


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Return non-zero if any finding is at or above this severity.",
)
def analyze_policy_cmd(input_path: Path, output_path: Path, fail_on_severity: str | None) -> None:
    with input_path.open("r", encoding="utf-8") as f:
        policy = json.load(f)

    findings = analyze_aws_policy(policy)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    if fail_on_severity:
        should_fail = any(
            _severity_meets_or_exceeds(f.get("severity", ""), fail_on_severity)
            for f in findings
        )
        if should_fail:
            raise click.ClickException(
                f"Found findings with severity >= {fail_on_severity}."
            )


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
def analyze_mfa_cmd(input_path: Path, output_path: Path) -> None:
    with input_path.open("r", encoding="utf-8") as f:
        identities = json.load(f)

    findings = analyze_mfa_coverage(identities)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--days", default=90, show_default=True, type=int)
def analyze_inactive_cmd(input_path: Path, output_path: Path, days: int) -> None:
    with input_path.open("r", encoding="utf-8") as f:
        identities = json.load(f)

    findings = analyze_inactive_accounts(identities, inactivity_days=days)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)


if __name__ == "__main__":
    cli()
