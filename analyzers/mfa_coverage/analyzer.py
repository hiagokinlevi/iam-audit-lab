"""
MFA Coverage Analyzer
=======================
Checks multi-factor authentication enrollment across all human IAM accounts.

MFA is one of the most effective controls against account compromise via
credential theft. This analyzer identifies:
  1. Human accounts with MFA not enabled
  2. Privileged accounts with MFA not enabled (higher severity)

Service accounts (IdentityType.SERVICE) are excluded from MFA analysis —
they authenticate with certificates, tokens, or API keys, not passwords + MFA.

Limitations:
  - MFA status is only as accurate as the data collected by the provider
    collectors. See notes in each collector for per-provider limitations.
  - Azure MFA status requires Azure AD Premium P1/P2 in the collector.
  - This analyzer does not distinguish between TOTP, SMS, hardware key, etc.
"""

from __future__ import annotations

from dataclasses import dataclass

from schemas.identity import AuditFinding, FindingCategory, FindingSeverity, IdentityRecord, IdentityType


@dataclass
class MFACoverageReport:
    """Summary statistics for MFA coverage in a set of identities."""

    total_human_accounts: int = 0
    mfa_enabled_count: int = 0
    mfa_disabled_count: int = 0
    privileged_without_mfa: int = 0

    @property
    def coverage_percent(self) -> float:
        """MFA coverage as a percentage of human accounts."""
        if self.total_human_accounts == 0:
            return 100.0
        return round((self.mfa_enabled_count / self.total_human_accounts) * 100, 1)

    @property
    def is_compliant(self) -> bool:
        """Returns True if all human accounts have MFA enabled."""
        return self.mfa_disabled_count == 0


def analyze_mfa_coverage(
    identities: list[IdentityRecord],
) -> tuple[list[AuditFinding], MFACoverageReport]:
    """
    Analyze MFA enrollment across all human IAM identities.

    Produces individual findings for each identity missing MFA, with escalated
    severity for privileged accounts. Also returns a summary report.

    Args:
        identities: List of collected IdentityRecord objects.

    Returns:
        A tuple of (findings, MFACoverageReport).
        - findings: List of AuditFinding for accounts missing MFA.
        - report: Summary statistics for the analyzed identity set.
    """
    findings: list[AuditFinding] = []
    report = MFACoverageReport()

    for identity in identities:
        # Only analyze human accounts — service accounts are not applicable
        if identity.identity_type != IdentityType.HUMAN:
            continue

        report.total_human_accounts += 1

        if identity.mfa_enabled:
            report.mfa_enabled_count += 1
            continue  # No finding needed

        # MFA is not enabled — generate a finding
        report.mfa_disabled_count += 1

        if identity.is_privileged:
            # Privileged account without MFA is critical — immediate remediation required
            report.privileged_without_mfa += 1
            severity = FindingSeverity.CRITICAL
            category = FindingCategory.PRIVILEGED_WITHOUT_MFA
            risk_score = 0.95
            title = f"CRITICAL: Privileged account missing MFA — {identity.identity_name}"
            description = (
                f"'{identity.identity_name}' has elevated permissions but does not have "
                "multi-factor authentication enabled. A compromised privileged account without "
                "MFA can be fully exploited with only a stolen password."
            )
            remediation = (
                "1. Enable MFA for this account immediately.\n"
                "2. Enforce MFA via an IAM policy or conditional access policy — do not rely "
                "on voluntary enrollment for privileged accounts.\n"
                "3. Consider requiring hardware security keys (FIDO2) for admin accounts.\n"
                "4. Review recent activity for signs of unauthorized access."
            )
        else:
            # Non-privileged account without MFA
            severity = FindingSeverity.HIGH
            category = FindingCategory.MFA_NOT_ENABLED
            risk_score = 0.65
            title = f"MFA not enabled: {identity.identity_name}"
            description = (
                f"'{identity.identity_name}' does not have multi-factor authentication enabled. "
                "Accounts without MFA are vulnerable to credential stuffing, phishing, and "
                "password spray attacks."
            )
            remediation = (
                "1. Enable MFA for this account.\n"
                "2. Enforce organization-wide MFA enrollment via policy.\n"
                "3. Consider conditional access policies that require MFA for all sign-ins."
            )

        finding = AuditFinding(
            category=category,
            severity=severity,
            provider=identity.provider,
            identity_id=identity.identity_id,
            identity_name=identity.identity_name,
            title=title,
            description=description,
            evidence=[
                f"MFA enabled: {identity.mfa_enabled}",
                f"Is privileged: {identity.is_privileged}",
                f"Attached policies: {', '.join(identity.attached_policies) or 'none'}",
            ],
            remediation=remediation,
            risk_score=risk_score,
        )
        findings.append(finding)

    return findings, report


def get_mfa_coverage_summary(report: MFACoverageReport) -> str:
    """Format MFA coverage statistics as a human-readable string."""
    lines = [
        f"Total human accounts: {report.total_human_accounts}",
        f"MFA enabled:          {report.mfa_enabled_count} ({report.coverage_percent}%)",
        f"MFA not enabled:      {report.mfa_disabled_count}",
        f"Privileged w/o MFA:   {report.privileged_without_mfa}",
        f"Compliant:            {'YES' if report.is_compliant else 'NO'}",
    ]
    return "\n".join(lines)
