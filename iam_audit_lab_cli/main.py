from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _filter_findings_by_min_severity(findings: list[dict[str, Any]], min_severity: str | None) -> list[dict[str, Any]]:
    if not min_severity:
        return findings

    threshold = SEVERITY_RANK[min_severity]
    filtered: list[dict[str, Any]] = []

    for finding in findings:
        sev = str(finding.get("severity", "")).lower()
        rank = SEVERITY_RANK.get(sev, 0)
        if rank >= threshold:
            filtered.append(finding)

    return filtered


@click.group()
def cli() -> None:
    pass


@cli.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["json", "markdown"], case_sensitive=False), default="markdown")
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Only include findings at or above this severity.",
)
def generate_report(input_path: Path, output_path: Path, output_format: str, min_severity: str | None) -> None:
    with input_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    findings = payload.get("findings", [])
    filtered_findings = _filter_findings_by_min_severity(findings, min_severity.lower() if min_severity else None)
    payload["findings"] = filtered_findings

    fmt = output_format.lower()
    if fmt == "json":
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        lines = ["# IAM Audit Report", "", "## Findings", ""]
        if not filtered_findings:
            lines.append("No findings match the selected severity threshold.")
        else:
            for fnd in filtered_findings:
                sev = fnd.get("severity", "unknown")
                title = fnd.get("title", "Untitled finding")
                lines.append(f"- **[{sev}]** {title}")
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    cli()
