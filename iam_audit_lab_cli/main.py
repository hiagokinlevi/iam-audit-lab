from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.mfa import analyze_mfa_coverage
from providers.loader import load_identities


@click.group()
def cli() -> None:
    """iam-audit-lab command line interface."""


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to identity JSON input.")
@click.option("--output", "output_path", required=False, type=click.Path(dir_okay=False, path_type=Path), help="Optional path to write JSON findings.")
def analyze_mfa_cmd(input_path: Path, output_path: Path | None) -> None:
    """Analyze MFA coverage and print results."""
    identities = load_identities(input_path)
    result = analyze_mfa_coverage(identities)

    click.echo(json.dumps(result, indent=2))

    if output_path is not None:
      parent = output_path.parent
      if not parent.exists():
          raise click.ClickException(f"Parent directory does not exist: {parent}")
      if output_path.exists():
          raise click.ClickException(f"Refusing to overwrite existing file: {output_path}")
      output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
      click.echo(f"Wrote MFA analysis JSON to: {output_path}")


if __name__ == "__main__":
    cli()
