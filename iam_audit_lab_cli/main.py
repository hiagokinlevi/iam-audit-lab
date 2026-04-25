from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from reports.generator import generate_markdown_report
from schemas.finding import AuditFinding
from schemas.identity import IdentityRecord


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path), help="Path to input identities JSON file.")
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path), help="Path to output report file (must match --format extension).")
@click.option("--format", "report_format", type=click.Choice(["md", "json"], case_sensitive=False), default="md", show_default=True, help="Report output format.")
def generate_report(input_path: Path, output_path: Path, report_format: str) -> None:
    """Generate a report from normalized identity data."""

    report_format = report_format.lower()
    expected_suffix = f".{report_format}"
    if output_path.suffix.lower() != expected_suffix:
        raise click.BadParameter(
            f"Output file extension must be '{expected_suffix}' when --format {report_format} is selected.",
            param_hint="--output",
        )

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    identities = [IdentityRecord.model_validate(item) for item in raw.get("identities", [])]
    findings = [AuditFinding.model_validate(item) for item in raw.get("findings", [])]

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if report_format == "json":
        payload = {
            "identities": [item.model_dump(mode="json") for item in identities],
            "findings": [item.model_dump(mode="json") for item in findings],
        }
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        markdown = generate_markdown_report(identities=identities, findings=findings)
        output_path.write_text(markdown, encoding="utf-8")

    click.echo(f"Report written to {output_path}")


if __name__ == "__main__":
    cli()
