"""
IAM Audit Report Generator
============================
Generates structured Markdown reports from audit findings and identity data.

Report types:
  - Executive summary: High-level metrics and critical findings for leadership
  - Full inventory: Complete list of all identities and their properties
  - MFA coverage: MFA status table for all human accounts
  - Privileged accounts: Focused view of all privileged identities and their permissions

All reports include a disclaimer reminding readers that the report contains
sensitive identity and permission data.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from analyzers.mfa_coverage.analyzer import MFACoverageReport
from schemas.identity import (
    AuditFinding,
    FindingSeverity,
    IdentityRecord,
    IdentityType,
)


# ---------------------------------------------------------------------------
# Severity ordering for report sections
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFORMATIONAL: 4,
}

_SEVERITY_EMOJI: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "[CRITICAL]",
    FindingSeverity.HIGH: "[HIGH]",
    FindingSeverity.MEDIUM: "[MEDIUM]",
    FindingSeverity.LOW: "[LOW]",
    FindingSeverity.INFORMATIONAL: "[INFO]",
}


def _severity_badge(severity: FindingSeverity) -> str:
    return _SEVERITY_EMOJI.get(severity, "[UNKNOWN]")


def generate_executive_summary(
    identities: list[IdentityRecord],
    findings: list[AuditFinding],
    provider: str,
    mfa_report: Optional[MFACoverageReport] = None,
) -> str:
    """
    Generate a concise executive summary report.

    Intended for security leadership reviews. Contains key metrics and
    critical/high findings only.

    Args:
        identities: Full list of collected identities.
        findings: All audit findings from all analyzers.
        provider: Cloud provider name (aws, azure, gcp, entra).
        mfa_report: Optional MFA coverage statistics.

    Returns:
        Markdown-formatted executive summary as a string.
    """
    now = datetime.now(timezone.utc).isoformat()
    total = len(identities)
    human_count = sum(1 for i in identities if i.identity_type == IdentityType.HUMAN)
    service_count = sum(1 for i in identities if i.identity_type == IdentityType.SERVICE)
    privileged_count = sum(1 for i in identities if i.is_privileged)

    # Findings by severity
    critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
    high = [f for f in findings if f.severity == FindingSeverity.HIGH]
    medium = [f for f in findings if f.severity == FindingSeverity.MEDIUM]
    low_info = [f for f in findings if f.severity in (FindingSeverity.LOW, FindingSeverity.INFORMATIONAL)]

    lines: list[str] = [
        f"# IAM Audit Report — {provider.upper()}",
        f"**Generated:** {now}",
        "",
        "> **Sensitivity notice:** This report contains identity names, permission details, and",
        "> security findings. Handle as sensitive data. Do not share externally without redaction.",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "### Identity Inventory",
        "",
        "| Metric | Count |",
        "|---|---|",
        f"| Total identities | {total} |",
        f"| Human accounts | {human_count} |",
        f"| Service accounts / roles | {service_count} |",
        f"| Privileged identities | {privileged_count} |",
        "",
        "### Findings Overview",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| Critical | {len(critical)} |",
        f"| High | {len(high)} |",
        f"| Medium | {len(medium)} |",
        f"| Low / Informational | {len(low_info)} |",
        f"| **Total** | **{len(findings)}** |",
        "",
    ]

    if mfa_report:
        lines += [
            "### MFA Coverage",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Human accounts | {mfa_report.total_human_accounts} |",
            f"| MFA enabled | {mfa_report.mfa_enabled_count} ({mfa_report.coverage_percent}%) |",
            f"| MFA not enabled | {mfa_report.mfa_disabled_count} |",
            f"| Privileged without MFA | {mfa_report.privileged_without_mfa} |",
            "",
        ]

    if critical:
        lines += [
            "---",
            "",
            "## Critical Findings — Immediate Action Required",
            "",
        ]
        for f in critical:
            lines.append(
                f"- **{_severity_badge(f.severity)} {f.identity_name}**: {f.title}"
            )
        lines.append("")

    if high:
        lines += [
            "## High Severity Findings",
            "",
        ]
        for f in high:
            lines.append(
                f"- **{_severity_badge(f.severity)} {f.identity_name}**: {f.title}"
            )
        lines.append("")

    return "\n".join(lines)


def generate_full_report(
    identities: list[IdentityRecord],
    findings: list[AuditFinding],
    provider: str,
    mfa_report: Optional[MFACoverageReport] = None,
) -> str:
    """
    Generate a comprehensive audit report with all findings, inventory, and metadata.

    Args:
        identities: Full list of collected identities.
        findings: All audit findings from all analyzers.
        provider: Cloud provider name.
        mfa_report: Optional MFA coverage statistics.

    Returns:
        Markdown-formatted full report as a string.
    """
    # Start with the executive summary
    report = generate_executive_summary(identities, findings, provider, mfa_report)

    # --- All findings section ---
    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    report += "\n---\n\n## All Findings\n\n"
    if not findings:
        report += "_No findings detected._\n"
    else:
        for finding in sorted_findings:
            report += f"### {_severity_badge(finding.severity)} {finding.title}\n\n"
            report += f"**Identity:** {finding.identity_name}  \n"
            report += f"**Category:** {finding.category.value}  \n"
            report += f"**Provider:** {finding.provider}  \n"
            report += f"**Risk Score:** {finding.risk_score:.2f}  \n"
            report += f"**Finding ID:** `{finding.finding_id}`\n\n"
            report += f"**Description:**  \n{finding.description}\n\n"
            if finding.evidence:
                report += "**Evidence:**\n"
                for ev in finding.evidence:
                    report += f"- {ev}\n"
                report += "\n"
            if finding.remediation:
                report += f"**Remediation:**  \n{finding.remediation}\n\n"
            report += "---\n\n"

    # --- Full inventory section ---
    report += "## Identity Inventory\n\n"
    report += (
        "| Name | Type | Provider | Status | MFA | Privileged | Policies |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    for identity in identities:
        policies = ", ".join(identity.attached_policies[:3])
        if len(identity.attached_policies) > 3:
            policies += f" (+{len(identity.attached_policies) - 3} more)"

        report += (
            f"| {identity.identity_name} "
            f"| {identity.identity_type.value} "
            f"| {identity.provider} "
            f"| {identity.status.value} "
            f"| {'Yes' if identity.mfa_enabled else 'No'} "
            f"| {'Yes' if identity.is_privileged else 'No'} "
            f"| {policies or '—'} |\n"
        )

    report += "\n"
    return report


def save_report(content: str, output_path: str | Path) -> None:
    """
    Write a report string to a file, creating parent directories if needed.

    Args:
        content: Markdown report content.
        output_path: File path for the output report.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Report saved to: {path.resolve()}")
