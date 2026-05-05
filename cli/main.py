from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from reports.generator import generate_json_report, generate_markdown_report


VALID_PROVIDERS = {"aws", "azure", "gcp", "entra"}


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("generate-report")
@click.option(
    "--identities",
    "identities_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to identities JSON file.",
)
@click.option(
    "--findings",
    "findings_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to findings JSON file.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--provider",
    type=click.Choice(sorted(VALID_PROVIDERS), case_sensitive=False),
    required=False,
    help="Filter report content to one provider (aws|azure|gcp|entra). Example: --provider aws",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Output report file path.",
)
def generate_report(
    identities_path: Path,
    findings_path: Path,
    output_format: str,
    provider: str | None,
    output_path: Path,
) -> None:
    """Generate Markdown or JSON report from identities and findings."""
    identities: list[dict[str, Any]] = json.loads(identities_path.read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = json.loads(findings_path.read_text(encoding="utf-8"))

    selected_provider = provider.lower() if provider else None
    if selected_provider:
        identities = [
            record
            for record in identities
            if str(record.get("provider", "")).lower() == selected_provider
        ]
        findings = [
            finding
            for finding in findings
            if str(finding.get("provider", "")).lower() == selected_provider
        ]

    output_format = output_format.lower()
    if output_format == "markdown":
        report_content = generate_markdown_report(identities=identities, findings=findings)
        output_path.write_text(report_content, encoding="utf-8")
    else:
        report_payload = generate_json_report(identities=identities, findings=findings)
        output_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    click.echo(f"Report written to: {output_path}")


if __name__ == "__main__":
    cli()
