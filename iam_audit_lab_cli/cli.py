from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _extract_aggregate_risk_score(findings_payload: Any, report_payload: Any) -> float:
    # Prefer explicit summary aggregate score if present in generated report payload
    if isinstance(report_payload, dict):
        summary = report_payload.get("summary")
        if isinstance(summary, dict):
            score = summary.get("aggregate_risk_score")
            if isinstance(score, (int, float)):
                return float(score)

    # Fallback: compute from findings risk score fields
    if isinstance(findings_payload, list):
        total = 0.0
        for finding in findings_payload:
            if isinstance(finding, dict):
                risk = finding.get("risk")
                if isinstance(risk, dict):
                    value = risk.get("score", 0)
                    if isinstance(value, (int, float)):
                        total += float(value)
        return total

    return 0.0


@cli.command("generate-report")
@click.option("--findings", "findings_path", type=click.Path(exists=True, path_type=Path), required=True, help="Path to findings JSON.")
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True, help="Path to output report JSON.")
@click.option(
    "--fail-on-risk-score",
    type=click.FloatRange(min=0, max=100, clamp=False),
    default=None,
    help="Exit non-zero if aggregate risk score is >= this threshold (0-100).",
)
def generate_report(findings_path: Path, output_path: Path, fail_on_risk_score: float | None) -> None:
    """Generate a report from findings JSON."""
    findings = _load_json(findings_path)

    # Minimal report shape used by tests/CLI consumers.
    # Existing downstream code can extend this while preserving summary.aggregate_risk_score.
    aggregate_score = _extract_aggregate_risk_score(findings, {})
    report = {
        "summary": {
            "aggregate_risk_score": aggregate_score,
        },
        "findings": findings,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    if fail_on_risk_score is not None and aggregate_score >= fail_on_risk_score:
        click.echo(
            f"Risk threshold exceeded: aggregate_risk_score={aggregate_score:.2f} >= {fail_on_risk_score:.2f}",
            err=True,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
