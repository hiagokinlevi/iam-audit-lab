from __future__ import annotations

import json
from pathlib import Path

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege_analysis import analyze_excessive_permissions
from analyzers.policy_analysis import analyze_policy_document
from reports.generator import generate_markdown_report, generate_json_report


def _load_identities(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        raise click.ClickException(f"Input file not found: {path}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid JSON in {path}: {exc}") from exc


@click.group()
def cli() -> None:
    """iam-audit-lab CLI."""


@cli.command("analyze-privileges")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def analyze_privileges_cmd(input_path: str, output_path: str) -> None:
    identities = _load_identities(input_path)
    findings = analyze_excessive_permissions(identities)
    Path(output_path).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-mfa")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def analyze_mfa_cmd(input_path: str, output_path: str) -> None:
    identities = _load_identities(input_path)
    findings = analyze_mfa_coverage(identities)
    Path(output_path).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-inactive")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option(
    "--max-age-days",
    default=90,
    show_default=True,
    type=click.IntRange(min=1),
    help="Maximum allowed inactivity age in days before flagging an identity.",
)
def analyze_inactive_cmd(input_path: str, output_path: str, max_age_days: int) -> None:
    identities = _load_identities(input_path)
    findings = analyze_inactive_accounts(identities, max_age_days=max_age_days)
    Path(output_path).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("analyze-policy")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
def analyze_policy_cmd(input_path: str, output_path: str) -> None:
    policy_json = Path(input_path).read_text(encoding="utf-8")
    findings = analyze_policy_document(policy_json)
    Path(output_path).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    click.echo(f"Wrote {len(findings)} findings to {output_path}")


@cli.command("generate-report")
@click.option("--identities", "identities_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--findings", "findings_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option("--format", "report_format", type=click.Choice(["markdown", "json"]), default="markdown")
def generate_report_cmd(identities_path: str, findings_path: str, output_path: str, report_format: str) -> None:
    identities = _load_identities(identities_path)
    findings = _load_identities(findings_path)

    if report_format == "markdown":
        content = generate_markdown_report(identities, findings)
    else:
        content = generate_json_report(identities, findings)

    Path(output_path).write_text(content, encoding="utf-8")
    click.echo(f"Wrote report to {output_path}")


if __name__ == "__main__":
    cli()
