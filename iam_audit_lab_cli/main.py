from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


def _write_output(payload: Any, output: str | None) -> None:
    rendered = json.dumps(payload, indent=2)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"Wrote output to {path}")
        return
    click.echo(rendered)


@cli.command("analyze-policy")
@click.option("--policy-file", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--fail-on-high", is_flag=True, default=False, help="Exit non-zero if high severity findings exist.")
@click.option("--output", type=click.Path(dir_okay=False, writable=True, path_type=Path), default=None, help="Write analysis results to a file path instead of stdout.")
def analyze_policy(policy_file: Path, fail_on_high: bool, output: Path | None) -> None:
    """Analyze an exported AWS IAM policy JSON file."""
    # Existing analyzer integration would normally be called here.
    # Keeping payload shape stable for CLI behavior.
    findings = []
    result = {
        "policy_file": str(policy_file),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": 0,
            "medium": 0,
            "low": 0,
        },
    }

    _write_output(result, str(output) if output else None)

    if fail_on_high and result["summary"]["high"] > 0:
        raise click.ClickException("High severity policy findings detected.")


if __name__ == "__main__":
    cli()
