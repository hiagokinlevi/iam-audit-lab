from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _severity_value(value: str | None) -> int:
    if not value:
        return 0
    return SEVERITY_ORDER.get(str(value).strip().lower(), 0)


def _filter_findings_by_min_severity(findings: list[dict[str, Any]], min_severity: str | None) -> list[dict[str, Any]]:
    if not min_severity:
        return findings

    min_value = _severity_value(min_severity)
    return [f for f in findings if _severity_value(f.get("severity")) >= min_value]


@click.command("generate-report")
@click.option("--identities", "identities_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--findings", "findings_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
@click.option("--format", "output_format", type=click.Choice(["markdown", "json"], case_sensitive=False), default="markdown", show_default=True)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Only include findings at or above this severity (default: include all severities).",
)
def generate_report(
    identities_path: Path,
    findings_path: Path,
    output_path: Path,
    output_format: str,
    min_severity: str | None,
) -> None:
    """Generate IAM audit report from identities + findings JSON."""

    identities = _load_json(identities_path)
    findings = _load_json(findings_path)

    if not isinstance(findings, list):
        raise click.ClickException("Findings input must be a JSON array")

    filtered_findings = _filter_findings_by_min_severity(findings, min_severity.lower() if min_severity else None)

    if output_format.lower() == "json":
        payload = {
            "identities": identities,
            "findings": filtered_findings,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        click.echo(f"Wrote JSON report: {output_path}")
        return

    # Markdown output
    lines: list[str] = []
    lines.append("# IAM Audit Report")
    lines.append("")
    if min_severity:
        lines.append(f"_Filtered by minimum severity: **{min_severity.lower()}**_")
        lines.append("")

    lines.append("## Findings")
    lines.append("")

    if not filtered_findings:
        lines.append("No findings matched the selected severity scope.")
    else:
        for idx, finding in enumerate(filtered_findings, start=1):
            sev = str(finding.get("severity", "unknown")).lower()
            title = finding.get("title") or finding.get("name") or f"Finding {idx}"
            desc = finding.get("description") or ""
            lines.append(f"### {idx}. {title}")
            lines.append(f"- Severity: **{sev}**")
            if desc:
                lines.append(f"- Description: {desc}")
            lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    click.echo(f"Wrote Markdown report: {output_path}")
