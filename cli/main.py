from __future__ import annotations

import json
from pathlib import Path

import click


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=False, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    required=False,
    default=None,
    help="Exit non-zero if any finding is at or above this severity.",
)
def analyze_privileges(input_path: Path, output_path: Path | None, fail_on_severity: str | None) -> None:
    """Analyze privilege findings from a JSON file.

    Expects input JSON with shape: {"findings": [{"severity": "low|medium|high|critical", ...}, ...]}
    """
    data = json.loads(input_path.read_text(encoding="utf-8"))
    findings = data.get("findings", [])

    if output_path:
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        click.echo(json.dumps(data))

    if fail_on_severity is None:
        return

    threshold = SEVERITY_ORDER[fail_on_severity.lower()]
    should_fail = any(
        SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 0) >= threshold
        for f in findings
    )

    if should_fail:
        raise click.ClickException(
            f"Found findings at or above severity '{fail_on_severity.lower()}'."
        )


if __name__ == "__main__":
    cli()
