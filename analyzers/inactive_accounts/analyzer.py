"""
Inactive Account Analyzer
==========================
Identifies IAM identities that have shown no activity within a configurable
time window. Inactive accounts increase the attack surface — compromised
credentials go undetected for longer when the account is not actively used.

Activity detection approach:
  - AWS: PasswordLastUsed (console), AccessKeyLastUsed (programmatic)
  - Azure: lastSignInDateTime from signInActivity (requires Azure AD P1/P2)
  - GCP: Last key usage (from key metadata) — Cloud Audit Logs analysis out of scope v0.1

Limitations:
  - AWS IAM only tracks PasswordLastUsed for console logins. Service account
    activity via access keys requires CloudTrail analysis (out of scope v0.1).
  - Azure signInActivity requires Azure AD Premium P1 or P2.
  - Accounts that have never been used are flagged separately as orphaned accounts
    when they have no creation activity either.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from schemas.identity import AuditFinding, FindingCategory, FindingSeverity, IdentityRecord

logger = logging.getLogger(__name__)


def _parse_last_activity(last_activity_at: Optional[str]) -> Optional[datetime]:
    """
    Parse a last_activity_at string into a timezone-aware datetime.

    Returns None if the value is None, 'never', or cannot be parsed.
    """
    if not last_activity_at or last_activity_at.lower() == "never":
        return None

    try:
        # Handle both Z suffix and +00:00 offset
        dt = datetime.fromisoformat(last_activity_at.replace("Z", "+00:00"))
        # Ensure timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError) as e:
        logger.debug("Could not parse last_activity_at '%s': %s", last_activity_at, str(e))
        return None


def analyze_inactive_accounts(
    identities: list[IdentityRecord],
    inactive_threshold_days: int = 90,
    reference_time: Optional[datetime] = None,
) -> list[AuditFinding]:
    """
    Identify accounts with no recorded activity within the threshold period.

    Two types of findings are produced:
    1. INACTIVE_ACCOUNT — account has activity but not within the threshold
    2. ORPHANED_ACCOUNT — account has never been used and was created more than
       the threshold days ago (suggesting it was provisioned but never activated)

    Args:
        identities: List of collected IdentityRecord objects.
        inactive_threshold_days: Number of days of inactivity to flag. Default 90.
        reference_time: The "now" reference point for inactivity calculation.
                        Defaults to the current UTC time. Override in tests.

    Returns:
        List of AuditFinding objects for inactive and orphaned accounts.
    """
    now = reference_time or datetime.now(timezone.utc)
    threshold_delta = timedelta(days=inactive_threshold_days)
    cutoff_date = now - threshold_delta

    findings: list[AuditFinding] = []

    for identity in identities:
        last_activity = _parse_last_activity(identity.last_activity_at)
        created_at = _parse_last_activity(identity.created_at)

        # Case 1: Account has last activity recorded but it is before the cutoff
        if last_activity is not None and last_activity < cutoff_date:
            days_inactive = (now - last_activity).days
            finding = AuditFinding(
                category=FindingCategory.INACTIVE_ACCOUNT,
                # Escalate to HIGH if the account is also privileged
                severity=FindingSeverity.HIGH if identity.is_privileged else FindingSeverity.MEDIUM,
                provider=identity.provider,
                identity_id=identity.identity_id,
                identity_name=identity.identity_name,
                title=f"Inactive account: no activity for {days_inactive} days",
                description=(
                    f"'{identity.identity_name}' has not been active for {days_inactive} days, "
                    f"exceeding the configured threshold of {inactive_threshold_days} days. "
                    "Unused accounts represent persistent credentials that may be compromised "
                    "without detection."
                ),
                evidence=[
                    f"Last recorded activity: {identity.last_activity_at}",
                    f"Days since last activity: {days_inactive}",
                    f"Threshold: {inactive_threshold_days} days",
                    f"Is privileged: {identity.is_privileged}",
                ],
                remediation=(
                    "1. Verify whether this account is still required.\n"
                    "2. If not required, disable or delete the account.\n"
                    "3. If still required but unused, investigate why it is not being used.\n"
                    "4. Consider implementing automated deprovisioning workflows for accounts "
                    "exceeding the inactivity threshold."
                ),
                risk_score=0.7 if identity.is_privileged else 0.45,
            )
            findings.append(finding)
            continue

        # Case 2: Account has never been used (last_activity is None or "never")
        # and was created more than the threshold ago
        if last_activity is None and created_at is not None and created_at < cutoff_date:
            days_since_creation = (now - created_at).days
            finding = AuditFinding(
                category=FindingCategory.ORPHANED_ACCOUNT,
                severity=FindingSeverity.MEDIUM,
                provider=identity.provider,
                identity_id=identity.identity_id,
                identity_name=identity.identity_name,
                title=f"Orphaned account: never used, created {days_since_creation} days ago",
                description=(
                    f"'{identity.identity_name}' has never been used and was created "
                    f"{days_since_creation} days ago. Orphaned accounts may represent "
                    "provisioning errors, departed employees, or abandoned projects. "
                    "They retain their permissions even when unused."
                ),
                evidence=[
                    f"Created: {identity.created_at}",
                    "Last activity: never",
                    f"Days since creation: {days_since_creation}",
                ],
                remediation=(
                    "1. Verify whether this account was intentionally created.\n"
                    "2. If it belongs to a departed employee or decommissioned service, "
                    "delete it immediately.\n"
                    "3. If it is legitimately needed, activate and configure it properly.\n"
                    "4. Ensure an owner is assigned to prevent future orphaning."
                ),
                risk_score=0.4,
            )
            findings.append(finding)

    return findings
