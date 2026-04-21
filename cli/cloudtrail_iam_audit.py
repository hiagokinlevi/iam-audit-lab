from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.aws_iam_change_history import audit_cloudtrail_iam_changes


@click.command("audit-cloudtrail-iam")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False), help="CloudTrail JSON file")
@click.option("--start-time", default=None, help="ISO8601 start time (inclusive)")
@click.option("--end-time", default=None, help="ISO8601 end time (inclusive)")
@click.option("--output", "output_path", default=None, type=click.Path(dir_okay=False), help="Write JSON report to file")
def audit_cloudtrail_iam_cmd(input_path: str, start_time: str | None, end_time: str | None, output_path: str | None) -> None:
    """Audit IAM change history from CloudTrail and generate a risk-oriented report."""
    report = audit_cloudtrail_iam_changes(input_path, start_time=start_time, end_time=end_time)

    rendered = json.dumps(report, indent=2)
    if output_path:
        Path(output_path).write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"Wrote report: {output_path}")
    else:
        click.echo(rendered)


if __name__ == "__main__":
    audit_cloudtrail_iam_cmd()
