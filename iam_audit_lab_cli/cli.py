from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.policy import analyze_aws_policy_document


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-policy")
@click.option("--policy-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--fail-on-severity", type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False), default=None)
@click.option("--json", "json_output", is_flag=True, default=False, help="Emit findings as JSON.")
def analyze_policy(policy_file: Path, fail_on_severity: str | None, json_output: bool) -> None:
    """Analyze an exported AWS IAM policy JSON document."""
    policy_doc = json.loads(policy_file.read_text(encoding="utf-8"))
    findings = analyze_aws_policy_document(policy_doc)

    if json_output:
        serialized = []
        for f in findings:
            statement = getattr(f, "statement", None)
            serialized.append(
                {
                    "rule_id": getattr(f, "rule_id", None),
                    "severity": str(getattr(f, "severity", "")).lower(),
                    "statement": {
                        "sid": statement.get("Sid") if isinstance(statement, dict) else None,
                        "index": getattr(f, "statement_index", None),
                    },
                    "message": getattr(f, "message", ""),
                }
            )
        click.echo(json.dumps({"findings": serialized}, indent=2))
        return

    if not findings:
        click.echo("No policy findings detected.")
    else:
        click.echo(f"Detected {len(findings)} policy finding(s):")
        for f in findings:
            click.echo(f"- [{str(getattr(f, 'severity', '')).upper()}] {getattr(f, 'rule_id', 'unknown')}: {getattr(f, 'message', '')}")

    if fail_on_severity:
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order[fail_on_severity.lower()]
        if any(order.get(str(getattr(f, "severity", "")).lower(), 0) >= threshold for f in findings):
            raise SystemExit(2)


if __name__ == "__main__":
    cli()
