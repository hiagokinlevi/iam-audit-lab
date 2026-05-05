from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.policy import analyze_aws_policy_document


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-policy")
@click.option("--policy-file", type=click.Path(exists=True, path_type=Path), required=True, help="Path to exported AWS IAM policy JSON.")
@click.option("--max-high", type=int, default=None, help="Fail (exit 1) if HIGH findings exceed this threshold.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format for findings.",
)
def analyze_policy(policy_file: Path, max_high: int | None, output_format: str) -> None:
    """Analyze offline AWS IAM policy JSON for escalation and wildcard risks."""
    data = json.loads(policy_file.read_text(encoding="utf-8"))
    findings = analyze_aws_policy_document(data)

    normalized_format = output_format.lower()

    if normalized_format == "json":
        serialized = [f.model_dump(mode="json") if hasattr(f, "model_dump") else f.dict() for f in findings]
        click.echo(json.dumps(serialized, indent=2, sort_keys=True))
    else:
        if not findings:
            click.echo("No policy findings detected.")
        else:
            click.echo("Policy Findings")
            click.echo("=" * 80)
            for finding in findings:
                severity = getattr(finding, "severity", "UNKNOWN")
                rule_id = getattr(finding, "rule_id", "unknown")
                resource = getattr(finding, "resource", "-")
                message = getattr(finding, "message", "")
                click.echo(f"[{severity}] {rule_id} | {resource}")
                click.echo(f"  {message}")

    high_count = sum(1 for f in findings if str(getattr(f, "severity", "")).upper() == "HIGH")
    if max_high is not None and high_count > max_high:
        raise click.ClickException(
            f"HIGH severity findings ({high_count}) exceeded threshold ({max_high})."
        )


if __name__ == "__main__":
    cli()
