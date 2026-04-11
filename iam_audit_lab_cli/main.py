"""
iam-audit-lab CLI
======================
Command-line interface for the IAM audit toolkit.

Commands:
  collect-identities  — Collect all IAM identities from a cloud provider
  analyze-privileges  — Detect excessive permission assignments
  analyze-policy      — Analyze exported AWS IAM policy JSON offline
  analyze-mfa         — Check MFA coverage for human accounts
  analyze-inactive    — Find accounts inactive beyond the threshold
  analyze-password-policy — Check the AWS account password policy baseline
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
from pydantic import ValidationError

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
# analyze-policy
# ---------------------------------------------------------------------------


@cli.command("analyze-policy")
@click.option(
    "--policy-file",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to an exported AWS IAM policy document JSON file.",
)
@click.option("--policy-name", default="ExportedPolicy", show_default=True)
@click.option("--policy-id", default="offline-policy", show_default=True)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
)
@click.option(
    "--fail-on",
    type=click.Choice(["medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Exit non-zero when the computed policy risk tier meets or exceeds this level.",
)
def analyze_policy(
    policy_file: str,
    policy_name: str,
    policy_id: str,
    output_format: str,
    fail_on: str | None,
) -> None:
    """Analyze an exported AWS IAM policy document without cloud credentials."""
    from analyzers.iam_policy_analyzer import IAMPolicyDocument, analyze

    policy_document = _load_json_object(policy_file, label="Policy file")
    policy = IAMPolicyDocument(
        policy_id=policy_id,
        policy_name=policy_name,
        policy_json=json.dumps(policy_document),
    )
    result = analyze(policy)

    if output_format.lower() == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(result.summary())
        for check in result.checks_fired:
            click.echo(
                f"  [{check.severity}] {check.check_id}: "
                f"{check.description} Evidence: {check.evidence}"
            )

    if fail_on and _tier_meets_threshold(result.risk_tier, fail_on):
        raise click.ClickException(
            f"Policy risk tier {result.risk_tier} meets --fail-on {fail_on.upper()}"
        )


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
# analyze-password-policy
# ---------------------------------------------------------------------------


@cli.command("analyze-password-policy")
@click.option("--policy-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Optional AWS GetAccountPasswordPolicy JSON export. "
                   "If omitted, the CLI calls the read-only IAM API.")
@click.option("--account-id", default=lambda: os.getenv("AWS_ACCOUNT_ID", "unknown"),
              show_default=True,
              help="Account identifier to include in the report.")
@click.option("--json-output", "json_output", is_flag=True,
              help="Print the full analyzer result as JSON.")
@click.option("--fail-on", type=click.Choice(["low", "medium", "high"], case_sensitive=False),
              default=None,
              help="Exit non-zero when a finding at or above this severity is present.")
def analyze_password_policy(
    policy_file: str | None,
    account_id: str,
    json_output: bool,
    fail_on: str | None,
) -> None:
    """Analyze the AWS account password policy for baseline weaknesses."""
    from analyzers.aws_password_policy_analyzer import analyze_password_policy as analyze_policy

    if policy_file:
        data = _load_json_object(policy_file, label="Password policy file")
        policy = data.get("PasswordPolicy", data)
        if policy is not None and not isinstance(policy, dict):
            raise click.ClickException(
                "Password policy file must contain a JSON object or an object with 'PasswordPolicy'."
            )
    else:
        iam = _get_aws_session().client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if error_code != "NoSuchEntity":
                raise
            policy = None

    result = analyze_policy(policy, account_id=account_id)

    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(result.summary())
        for finding in result.findings:
            click.echo(f"  [{finding.severity}] {finding.rule_id}: {finding.title}")

    if fail_on and _has_finding_at_or_above(result.findings, fail_on):
        raise click.ClickException(f"Password policy findings met --fail-on {fail_on}.")


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
        data = _load_json_array(identities_file, label="Identities file")
        identities = []
        for index, item in enumerate(data):
            try:
                identities.append(IdentityRecord.model_validate(item))
            except ValidationError as exc:
                raise click.ClickException(f"Identities file entry {index} is invalid: {exc}") from exc
        return identities

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


def _load_json_file(path: str | Path, *, label: str):
    """Load a JSON document from disk and return the decoded payload."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise click.ClickException(f"Unable to read {label.lower()}: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"{label} must contain valid JSON: {exc}") from exc


def _load_json_object(path: str | Path, *, label: str) -> dict:
    """Load a JSON object from disk for offline analyzer inputs."""
    payload = _load_json_file(path, label=label)
    if not isinstance(payload, dict):
        raise click.ClickException(f"{label} must contain a top-level JSON object.")
    return payload


def _load_json_array(path: str | Path, *, label: str) -> list:
    """Load a JSON array from disk for offline analyzer inputs."""
    payload = _load_json_file(path, label=label)
    if not isinstance(payload, list):
        raise click.ClickException(f"{label} must contain a top-level JSON array.")
    return payload


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


def _tier_meets_threshold(tier: str, threshold: str) -> bool:
    """Return True when a policy risk tier meets or exceeds a threshold."""
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    return order[tier.upper()] >= order[threshold.upper()]


def _has_finding_at_or_above(findings: list, minimum: str) -> bool:
    order = {"low": 1, "medium": 2, "high": 3}
    threshold = order[minimum.lower()]
    return any(order.get(finding.severity.lower(), 0) >= threshold for finding in findings)


if __name__ == "__main__":
    cli()
