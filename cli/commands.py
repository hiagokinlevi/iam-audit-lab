from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.privileges import analyze_privileges as run_privilege_analysis


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to collected identities JSON file")
@click.option("--output", "output_path", required=False, type=click.Path(dir_okay=False, writable=True, path_type=Path), help="Optional path to write findings JSON")
def analyze_privileges_command(input_path: Path, output_path: Path | None) -> None:
    """Analyze identities for excessive privileges."""
    result = run_privilege_analysis(input_path)

    # Preserve existing stdout behavior (JSON payload).
    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    rendered = json.dumps(payload, indent=2)
    click.echo(rendered)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
