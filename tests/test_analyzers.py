"""
Tests for analyzers: excessive_permissions, inactive_accounts, mfa_coverage
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from analyzers.excessive_permissions.analyzer import analyze_excessive_permissions
from analyzers.inactive_accounts.analyzer import analyze_inactive_accounts
from analyzers.mfa_coverage.analyzer import analyze_mfa_coverage, get_mfa_coverage_summary
from schemas.identity import (
    AuditFinding,
    FindingCategory,
    FindingSeverity,
    IdentityRecord,
    IdentityStatus,
    IdentityType,
)


# ---------------------------------------------------------------------------
# Test fixtures — reusable identity records
# ---------------------------------------------------------------------------


def make_identity(
    name: str = "test-user",
    identity_type: IdentityType = IdentityType.HUMAN,
    provider: str = "aws",
    mfa_enabled: bool = True,
    is_privileged: bool = False,
    attached_policies: list[str] | None = None,
    last_activity_at: str | None = None,
    created_at: str | None = None,
    status: IdentityStatus = IdentityStatus.ACTIVE,
) -> IdentityRecord:
    """Factory function to create test IdentityRecord objects."""
    return IdentityRecord(
        identity_id=f"id_{name.replace('-', '_')}",
        identity_name=name,
        identity_type=identity_type,
        provider=provider,
        status=status,
        mfa_enabled=mfa_enabled,
        is_privileged=is_privileged,
        attached_policies=attached_policies or [],
        last_activity_at=last_activity_at,
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# Excessive permissions analyzer tests
# ---------------------------------------------------------------------------


class TestExcessivePermissionsAnalyzer:
    def test_no_findings_for_clean_identity(self) -> None:
        identity = make_identity(attached_policies=["AmazonEC2ReadOnlyAccess"])
        findings = analyze_excessive_permissions([identity])
        assert findings == []

    def test_critical_finding_for_administrator_access(self) -> None:
        identity = make_identity(attached_policies=["AdministratorAccess"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].category == FindingCategory.EXCESSIVE_PERMISSIONS
        assert "AdministratorAccess" in findings[0].title

    def test_high_finding_for_power_user_access(self) -> None:
        identity = make_identity(attached_policies=["PowerUserAccess"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH

    def test_medium_finding_for_s3_full_access(self) -> None:
        identity = make_identity(attached_policies=["AmazonS3FullAccess"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM

    def test_multiple_findings_for_multiple_excessive_policies(self) -> None:
        identity = make_identity(attached_policies=["AdministratorAccess", "AmazonS3FullAccess"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 2

    def test_finding_includes_identity_metadata(self) -> None:
        identity = make_identity(name="deploy-bot", attached_policies=["AdministratorAccess"])
        findings = analyze_excessive_permissions([identity])
        assert findings[0].identity_name == "deploy-bot"
        assert findings[0].provider == "aws"

    def test_finding_includes_remediation(self) -> None:
        identity = make_identity(attached_policies=["AdministratorAccess"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings[0].remediation) > 0

    def test_azure_excessive_roles_detected(self) -> None:
        identity = make_identity(provider="azure", attached_policies=["Owner"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_gcp_excessive_roles_detected(self) -> None:
        identity = make_identity(provider="gcp", attached_policies=["roles/owner"])
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_gcp_public_allusers_viewer_binding_is_detected(self) -> None:
        identity = make_identity(
            name="allUsers",
            provider="gcp",
            attached_policies=["roles/viewer"],
        )
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert findings[0].title == "Public GCP IAM binding: allUsers -> roles/viewer"

    def test_gcp_public_allauthenticatedusers_admin_binding_is_high(self) -> None:
        identity = make_identity(
            name="allAuthenticatedUsers",
            provider="gcp",
            attached_policies=["roles/iam.serviceAccountAdmin"],
        )
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH
        assert findings[0].risk_score == 0.75

    def test_gcp_public_owner_binding_is_critical_without_duplicate_generic_finding(self) -> None:
        identity = make_identity(
            name="allUsers",
            provider="gcp",
            attached_policies=["roles/owner"],
        )
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert "Public GCP IAM binding" in findings[0].title

    def test_gcp_public_binding_with_multiple_roles_produces_multiple_findings(self) -> None:
        identity = make_identity(
            name="allUsers",
            provider="gcp",
            attached_policies=["roles/viewer", "roles/editor"],
        )
        findings = analyze_excessive_permissions([identity])
        assert len(findings) == 2
        severities = {finding.severity for finding in findings}
        assert severities == {FindingSeverity.MEDIUM, FindingSeverity.HIGH}

    def test_public_principal_name_on_non_gcp_identity_is_not_treated_as_gcp_public_binding(
        self,
    ) -> None:
        identity = make_identity(
            name="allUsers",
            provider="aws",
            attached_policies=["AmazonEC2ReadOnlyAccess"],
        )
        findings = analyze_excessive_permissions([identity])
        assert findings == []

    def test_empty_identity_list_returns_no_findings(self) -> None:
        assert analyze_excessive_permissions([]) == []

    def test_risk_score_for_critical_is_1_0(self) -> None:
        identity = make_identity(attached_policies=["AdministratorAccess"])
        findings = analyze_excessive_permissions([identity])
        assert findings[0].risk_score == 1.0


# ---------------------------------------------------------------------------
# Inactive accounts analyzer tests
# ---------------------------------------------------------------------------


class TestInactiveAccountsAnalyzer:
    @pytest.fixture
    def reference_time(self) -> datetime:
        return datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_active_account_no_finding(self, reference_time: datetime) -> None:
        # Last activity 10 days before reference — well within 90-day threshold
        recent = (reference_time - timedelta(days=10)).isoformat()
        identity = make_identity(last_activity_at=recent)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert findings == []

    def test_inactive_account_flagged(self, reference_time: datetime) -> None:
        # Last activity 100 days ago — exceeds 90-day threshold
        old = (reference_time - timedelta(days=100)).isoformat()
        identity = make_identity(last_activity_at=old)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.INACTIVE_ACCOUNT

    def test_inactive_privileged_account_is_high_severity(self, reference_time: datetime) -> None:
        old = (reference_time - timedelta(days=100)).isoformat()
        identity = make_identity(last_activity_at=old, is_privileged=True)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert findings[0].severity == FindingSeverity.HIGH

    def test_inactive_non_privileged_account_is_medium(self, reference_time: datetime) -> None:
        old = (reference_time - timedelta(days=100)).isoformat()
        identity = make_identity(last_activity_at=old, is_privileged=False)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert findings[0].severity == FindingSeverity.MEDIUM

    def test_never_used_account_is_orphaned(self, reference_time: datetime) -> None:
        # Created 100 days ago but never used
        old_creation = (reference_time - timedelta(days=100)).isoformat()
        identity = make_identity(last_activity_at="never", created_at=old_creation)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.ORPHANED_ACCOUNT

    def test_recently_created_never_used_not_flagged(self, reference_time: datetime) -> None:
        # Created 10 days ago and never used — too recent to flag
        recent_creation = (reference_time - timedelta(days=10)).isoformat()
        identity = make_identity(last_activity_at="never", created_at=recent_creation)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert findings == []

    def test_custom_threshold(self, reference_time: datetime) -> None:
        # 31 days ago — inactive under 90-day threshold but active under 30-day threshold
        slightly_old = (reference_time - timedelta(days=31)).isoformat()
        identity = make_identity(last_activity_at=slightly_old)

        # With 30-day threshold — should be flagged
        findings_30 = analyze_inactive_accounts(
            [identity], inactive_threshold_days=30, reference_time=reference_time
        )
        assert len(findings_30) == 1

        # With 90-day threshold — should not be flagged
        findings_90 = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        assert findings_90 == []

    def test_finding_includes_days_inactive_in_evidence(self, reference_time: datetime) -> None:
        old = (reference_time - timedelta(days=150)).isoformat()
        identity = make_identity(last_activity_at=old)
        findings = analyze_inactive_accounts(
            [identity], inactive_threshold_days=90, reference_time=reference_time
        )
        evidence_text = " ".join(findings[0].evidence)
        assert "150" in evidence_text


# ---------------------------------------------------------------------------
# MFA coverage analyzer tests
# ---------------------------------------------------------------------------


class TestMFACoverageAnalyzer:
    def test_no_findings_all_mfa_enabled(self) -> None:
        identities = [
            make_identity(name="alice", mfa_enabled=True),
            make_identity(name="bob", mfa_enabled=True),
        ]
        findings, report = analyze_mfa_coverage(identities)
        assert findings == []
        assert report.is_compliant is True
        assert report.coverage_percent == 100.0

    def test_finding_for_human_without_mfa(self) -> None:
        identity = make_identity(name="charlie", mfa_enabled=False)
        findings, report = analyze_mfa_coverage([identity])
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MFA_NOT_ENABLED
        assert findings[0].severity == FindingSeverity.HIGH

    def test_critical_finding_for_privileged_without_mfa(self) -> None:
        identity = make_identity(
            name="admin-user",
            mfa_enabled=False,
            is_privileged=True,
        )
        findings, report = analyze_mfa_coverage([identity])
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].category == FindingCategory.PRIVILEGED_WITHOUT_MFA
        assert report.privileged_without_mfa == 1

    def test_service_accounts_excluded_from_mfa_analysis(self) -> None:
        service = make_identity(
            name="svc-account",
            identity_type=IdentityType.SERVICE,
            mfa_enabled=False,  # Service accounts never have MFA
        )
        findings, report = analyze_mfa_coverage([service])
        assert findings == []
        assert report.total_human_accounts == 0

    def test_coverage_percent_calculation(self) -> None:
        identities = [
            make_identity(name="alice", mfa_enabled=True),
            make_identity(name="bob", mfa_enabled=True),
            make_identity(name="charlie", mfa_enabled=False),
            make_identity(name="diana", mfa_enabled=False),
        ]
        _, report = analyze_mfa_coverage(identities)
        assert report.total_human_accounts == 4
        assert report.mfa_enabled_count == 2
        assert report.mfa_disabled_count == 2
        assert report.coverage_percent == 50.0

    def test_report_compliant_when_zero_accounts(self) -> None:
        _, report = analyze_mfa_coverage([])
        assert report.is_compliant is True
        assert report.coverage_percent == 100.0

    def test_coverage_summary_string_format(self) -> None:
        identities = [make_identity(mfa_enabled=True)]
        _, report = analyze_mfa_coverage(identities)
        summary = get_mfa_coverage_summary(report)
        assert "Total human accounts" in summary
        assert "MFA enabled" in summary
        assert "Compliant" in summary

    def test_risk_score_higher_for_privileged(self) -> None:
        privileged = make_identity(name="admin", mfa_enabled=False, is_privileged=True)
        normal = make_identity(name="user", mfa_enabled=False, is_privileged=False)
        findings, _ = analyze_mfa_coverage([privileged, normal])

        privileged_finding = next(f for f in findings if f.identity_name == "admin")
        normal_finding = next(f for f in findings if f.identity_name == "user")

        assert privileged_finding.risk_score > normal_finding.risk_score
