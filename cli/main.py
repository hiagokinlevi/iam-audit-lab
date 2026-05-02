from __future__ import annotations

import json
from pathlib import Path

import click


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to exported AWS IAM policy JSON.")
@click.option("--fail-on-high", is_flag=True, default=False, help="Exit non-zero when high severity findings are present.")
@click.option(
    "--output",
    "output_path",
    required=False,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Optional file path to write findings JSON (creates parent dirs, overwrites existing file).",
)
def analyze_policy(input_path: Path, fail_on_high: bool, output_path: Path | None) -> None:
    """Analyze an exported AWS IAM policy file for risky patterns."""

    # Local import to keep CLI startup light.
    from analyzers.policy import analyze_aws_policy_document

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    findings = analyze_aws_policy_document(raw)

    rendered = json.dumps(findings, indent=2)

    if output_path is not None:
      output_path.parent.mkdir(parents=True, exist_ok=True)
      output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
      click.echo(rendered)

    if fail_on_high and any(f.get("severity") == "high" for f in findings):
        raise click.ClickException("High severity policy findings detected.")


if __name__ == "__main__":
    cli()
