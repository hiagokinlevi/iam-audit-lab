"""
iam-audit-lab CLI
======================
Command-line interface for the IAM audit toolkit.

Commands:
  collect-identities  — Collect all IAM identities from a cloud provider
  analyze-privileges  — Detect excessive permission assignments
  analyze-mfa         — Check MFA coverage for human accounts
  analyze-inactive    — Find accounts inactive beyond the threshold
  generate-report     — Run all analyzers and generate a Markdown report

Usage:
  k1n-iam-audit collect-identities --provider aws
  k1n-iam-audit analyze-privileges --provider aws
  k1n-iam-audit generate-report --provider aws --output ./output/report.md
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv

# Load .env file before processing any commands
load_dotenv()


@click.group()
@click.version_option(version="0.1.0", prog_name="k1n-iam-audit")
def cli() -> None:
    """
    iam-audit-lab — IAM audit toolkit for AWS, Azure, GCP, and Entra.

    \b
    Authorization reminder:
      Only run this tool against cloud accounts you own or are authorized to audit.
      All API calls are read-only. Results may contain sensitive identity data —
      store output files securely.
    """


def _get_aws_session() -> "boto3.Session":
    """Create a boto3 session from environment or profile."""
    import boto3
    profile = os.getenv("AWS_PROFILE", "default")
    region = os.getenv("AWS_REGION", "us-east-1")
    return boto3.Session(profile_name=profile, region_name=region)


# ---------------------------------------------------------------------------
# collect-identities
# ---------------------------------------------------------------------------


@cli.command("collect-identities")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "entra"], case_sensitive=False),
    default=lambda: os.getenv("PROVIDER", "aws"),
    show_default=True,
    help="Cloud provider to collect identities from.",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Optional path to write collected identities as JSON.",
)
def collect_identities(provider: str, output: str | None) -> None:
    """Collect all IAM identities from the specified cloud provider."""
    click.echo(f"Collecting identities from {provider.upper()}...")

    if provider == "aws":
        from providers.aws.identity_collector import collect_all_identities
        session = _get_aws_session()
        identities = collect_all_identities(session)

    elif provider in ("azure", "entra"):
        from providers.azure.identity_collector import collect_all_identities
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        if not tenant_id:
            click.echo("ERROR: AZURE_TENANT_ID is required for Azure/Entra collection.", err=True)
            sys.exit(1)
        identities = collect_all_identities(tenant_id)

    elif provider == "gcp":
        from providers.gcp.identity_collector import collect_all_identities
        project_id = os.environ.get("GCP_PROJECT_ID")
        if not project_id:
            click.echo("ERROR: GCP_PROJECT_ID is required for GCP collection.", err=True)
            sys.exit(1)
        identities = collect_all_identities(project_id)

    else:
        click.echo(f"Unsupported provider: {provider}", err=True)
        sys.exit(1)

    click.echo(f"Collected {len(identities)} identities.")

    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [i.model_dump(mode="json") for i in identities]
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        click.echo(f"Identities written to: {path.resolve()}")

    # Print a summary table to stdout
    privileged = sum(1 for i in identities if i.is_privileged)
    human = sum(1 for i in identities if i.identity_type.value == "human")
    service = sum(1 for i in identities if i.identity_type.value == "service")
    click.echo(f"\nSummary:")
    click.echo(f"  Human accounts:   {human}")
    click.echo(f"  Service accounts: {service}")
    click.echo(f"  Privileged:       {privileged}")


# ---------------------------------------------------------------------------
# analyze-privileges
# ---------------------------------------------------------------------------


@cli.command("analyze-privileges")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
              default=lambda: os.getenv("PROVIDER", "aws"))
@click.option("--identities-file", type=click.Path(exists=True), default=None,
              help="Path to a JSON file of previously collected identities. "
                   "If not provided, identities are collected fresh.")
def analyze_privileges(provider: str, identities_file: str | None) -> None:
    """Analyze collected identities for excessive permission assignments."""
    from analyzers.excessive_permissions.analyzer import analyze_excessive_permissions

    identities = _load_or_collect_identities(provider, identities_file)
    click.echo(f"Analyzing {len(identities)} identities for excessive permissions...")

    findings = analyze_excessive_permissions(identities)
    _print_findings_summary(findings)


# ---------------------------------------------------------------------------
# analyze-mfa
# ---------------------------------------------------------------------------


@cli.command("analyze-mfa")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
              default=lambda: os.getenv("PROVIDER", "aws"))
@click.option("--identities-file", type=click.Path(exists=True), default=None)
def analyze_mfa(provider: str, identities_file: str | None) -> None:
    """Check MFA enrollment for all human IAM accounts."""
    from analyzers.mfa_coverage.analyzer import analyze_mfa_coverage, get_mfa_coverage_summary

    identities = _load_or_collect_identities(provider, identities_file)
    click.echo(f"Analyzing MFA coverage for {len(identities)} identities...")

    findings, mfa_report = analyze_mfa_coverage(identities)
    click.echo("\n" + get_mfa_coverage_summary(mfa_report))
    _print_findings_summary(findings)


# ---------------------------------------------------------------------------
# analyze-inactive
# ---------------------------------------------------------------------------


@cli.command("analyze-inactive")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
              default=lambda: os.getenv("PROVIDER", "aws"))
@click.option("--inactive-days", type=int,
              default=lambda: int(os.getenv("INACTIVE_THRESHOLD_DAYS", "90")),
              show_default=True,
              help="Number of days of inactivity before flagging an account.")
@click.option("--identities-file", type=click.Path(exists=True), default=None)
def analyze_inactive(provider: str, inactive_days: int, identities_file: str | None) -> None:
    """Find accounts that have been inactive beyond the threshold."""
    from analyzers.inactive_accounts.analyzer import analyze_inactive_accounts

    identities = _load_or_collect_identities(provider, identities_file)
    click.echo(
        f"Analyzing {len(identities)} identities for inactivity (threshold: {inactive_days} days)..."
    )

    findings = analyze_inactive_accounts(identities, inactive_threshold_days=inactive_days)
    _print_findings_summary(findings)


# ---------------------------------------------------------------------------
# generate-report
# ---------------------------------------------------------------------------


@cli.command("generate-report")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
              default=lambda: os.getenv("PROVIDER", "aws"))
@click.option("--output", type=click.Path(), default=None,
              help="Output file path. Defaults to ./output/<provider>_iam_audit.md")
@click.option("--inactive-days", type=int,
              default=lambda: int(os.getenv("INACTIVE_THRESHOLD_DAYS", "90")))
@click.option("--identities-file", type=click.Path(exists=True), default=None)
def generate_report(
    provider: str,
    output: str | None,
    inactive_days: int,
    identities_file: str | None,
) -> None:
    """Run all analyzers and generate a comprehensive Markdown audit report."""
    from analyzers.excessive_permissions.analyzer import analyze_excessive_permissions
    from analyzers.inactive_accounts.analyzer import analyze_inactive_accounts
    from analyzers.mfa_coverage.analyzer import analyze_mfa_coverage
    from reports.generator import generate_full_report, save_report

    identities = _load_or_collect_identities(provider, identities_file)
    click.echo(f"Running all analyzers on {len(identities)} identities...")

    # Run all analyzers
    privilege_findings = analyze_excessive_permissions(identities)
    inactive_findings = analyze_inactive_accounts(identities, inactive_threshold_days=inactive_days)
    mfa_findings, mfa_report = analyze_mfa_coverage(identities)

    all_findings = privilege_findings + inactive_findings + mfa_findings
    click.echo(f"Total findings: {len(all_findings)}")

    # Generate report
    report_content = generate_full_report(identities, all_findings, provider, mfa_report)

    output_path = output or os.path.join(
        os.getenv("OUTPUT_DIR", "./output"),
        f"{provider}_iam_audit.md",
    )
    save_report(report_content, output_path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_or_collect_identities(provider: str, identities_file: str | None) -> list:
    """
    Load identities from a JSON file or collect them fresh from the provider.
    """
    from schemas.identity import IdentityRecord

    if identities_file:
        data = json.loads(Path(identities_file).read_text(encoding="utf-8"))
        return [IdentityRecord.model_validate(item) for item in data]

    # Collect fresh
    if provider == "aws":
        from providers.aws.identity_collector import collect_all_identities
        return collect_all_identities(_get_aws_session())

    elif provider in ("azure", "entra"):
        from providers.azure.identity_collector import collect_all_identities
        tenant_id = os.environ.get("AZURE_TENANT_ID", "")
        return collect_all_identities(tenant_id)

    elif provider == "gcp":
        from providers.gcp.identity_collector import collect_all_identities
        return collect_all_identities(os.environ.get("GCP_PROJECT_ID", ""))

    return []


def _print_findings_summary(findings: list) -> None:
    """Print a concise findings summary to stdout."""
    from schemas.identity import FindingSeverity

    critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    medium = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    low = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    click.echo(f"\nFindings: {len(findings)} total")
    click.echo(f"  Critical: {critical}")
    click.echo(f"  High:     {high}")
    click.echo(f"  Medium:   {medium}")
    click.echo(f"  Low:      {low}")

    if findings:
        click.echo("\nTop findings:")
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True)[:5]:
            click.echo(f"  [{f.severity.value.upper()}] {f.title}")


if __name__ == "__main__":
    cli()
