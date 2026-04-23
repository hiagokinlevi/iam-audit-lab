from __future__ import annotations

from collections import Counter
from typing import Iterable

from schemas.models import AuditFinding, IdentityRecord


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _finding_sort_key(finding: AuditFinding) -> tuple[int, str, str]:
    severity_rank = _SEVERITY_ORDER.get(str(finding.severity).lower(), 99)
    provider = str(getattr(finding, "provider", "") or "")
    account_id = str(getattr(finding, "account_id", "") or getattr(finding, "principal_id", "") or "")
    return (severity_rank, provider, account_id)


def generate_markdown_report(
    identities: Iterable[IdentityRecord],
    findings: Iterable[AuditFinding],
) -> str:
    identities = list(identities)
    findings = list(findings)

    severity_counts = Counter(str(f.severity).title() for f in findings)

    lines: list[str] = []
    lines.append("# IAM Audit Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total identities: **{len(identities)}**")
    lines.append(f"- Total findings: **{len(findings)}**")
    if findings:
        lines.append(
            "- Findings by severity: "
            + ", ".join(
                f"{sev}: **{severity_counts.get(sev, 0)}**"
                for sev in ("Critical", "High", "Medium", "Low")
                if severity_counts.get(sev, 0)
            )
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings detected.")
    else:
        for finding in sorted(findings, key=_finding_sort_key):
            lines.append(
                f"- **[{str(finding.severity).upper()}]** {finding.title} "
                f"({getattr(finding, 'provider', 'unknown')}:{getattr(finding, 'account_id', getattr(finding, 'principal_id', 'n/a'))})"
            )
            if getattr(finding, "description", None):
                lines.append(f"  - {finding.description}")
    lines.append("")

    lines.append("## Full Inventory")
    lines.append("")
    if not identities:
        lines.append("No identities collected.")
    else:
        lines.append("| Provider | Account/Project | Principal | Type | MFA | Privileged |")
        lines.append("|---|---|---|---|---:|---:|")
        for identity in identities:
            lines.append(
                "| "
                f"{identity.provider} | "
                f"{identity.account_id} | "
                f"{identity.principal_name} | "
                f"{identity.principal_type} | "
                f"{('Yes' if identity.mfa_enabled else 'No')} | "
                f"{('Yes' if identity.is_privileged else 'No')} |"
            )

    lines.append("")
    return "\n".join(lines)
