from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from analyzers.inactive_accounts import analyze_inactive_accounts
from analyzers.mfa_coverage import analyze_mfa_coverage
from analyzers.privilege_analyzer import analyze_excessive_permissions
from providers.aws import collect_aws_identities
from providers.azure import collect_azure_identities
from providers.gcp import collect_gcp_identities


def _to_dict(item: Any) -> dict[str, Any]:
    if hasattr(item, "model_dump"):
        return item.model_dump()
    if hasattr(item, "dict"):
        return item.dict()
    if isinstance(item, dict):
        return item
    return {"value": str(item)}


def _collect_identities(aws: bool, azure: bool, gcp: bool) -> list[Any]:
    identities: list[Any] = []
    if aws:
        identities.extend(collect_aws_identities())
    if azure:
        identities.extend(collect_azure_identities())
    if gcp:
        identities.extend(collect_gcp_identities())
    return identities


@click.command("audit")
@click.option("--aws/--no-aws", default=True, show_default=True, help="Include AWS identity collection")
@click.option("--azure/--no-azure", default=True, show_default=True, help="Include Azure identity collection")
@click.option("--gcp/--no-gcp", default=True, show_default=True, help="Include GCP identity collection")
@click.option("--inactive-days", type=int, default=90, show_default=True, help="Inactive account threshold in days")
@click.option("--json-out", type=click.Path(path_type=Path), default=None, help="Optional path to write JSON results")
def audit_command(aws: bool, azure: bool, gcp: bool, inactive_days: int, json_out: Path | None) -> None:
    """Run a full IAM audit and output findings in terminal and JSON formats."""
    if not any([aws, azure, gcp]):
        raise click.ClickException("At least one provider must be enabled.")

    click.echo("[+] Collecting identities...")
    identities = _collect_identities(aws=aws, azure=azure, gcp=gcp)
    click.echo(f"[+] Collected {len(identities)} identities")

    click.echo("[+] Running analyzers...")
    privilege_findings = analyze_excessive_permissions(identities)
    inactive_findings = analyze_inactive_accounts(identities, inactive_days=inactive_days)
    mfa_findings = analyze_mfa_coverage(identities)

    findings: list[Any] = [*privilege_findings, *inactive_findings, *mfa_findings]

    click.echo("\n=== IAM AUDIT FINDINGS ===")
    if not findings:
        click.echo("No findings detected.")
    else:
        for i, finding in enumerate(findings, start=1):
            data = _to_dict(finding)
            finding_id = data.get("id") or data.get("rule_id") or f"finding-{i}"
            severity = data.get("severity", "UNKNOWN")
            title = data.get("title") or data.get("description") or "Unnamed finding"
            target = data.get("resource") or data.get("identity") or data.get("subject") or "n/a"
            click.echo(f"{i}. [{severity}] {finding_id} :: {title} (target: {target})")

    payload = {
        "summary": {
            "total_identities": len(identities),
            "total_findings": len(findings),
            "providers": {"aws": aws, "azure": azure, "gcp": gcp},
            "inactive_days": inactive_days,
        },
        "findings": [_to_dict(f) for f in findings],
    }

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        click.echo(f"\n[+] JSON report written to: {json_out}")
