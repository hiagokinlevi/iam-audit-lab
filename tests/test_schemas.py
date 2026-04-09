"""
Tests for schemas/identity.py
"""

from __future__ import annotations

import pytest

from schemas.identity import (
    AuditFinding,
    FindingCategory,
    FindingSeverity,
    IdentityRecord,
    IdentityStatus,
    IdentityType,
    RiskScore,
)


# ---------------------------------------------------------------------------
# IdentityRecord tests
# ---------------------------------------------------------------------------


class TestIdentityRecord:
    def test_minimal_valid_record(self) -> None:
        record = IdentityRecord(
            identity_id="user123",
            identity_name="alice",
            identity_type=IdentityType.HUMAN,
            provider="aws",
        )
        assert record.identity_id == "user123"
        assert record.identity_name == "alice"
        assert record.identity_type == IdentityType.HUMAN
        assert record.provider == "aws"

    def test_default_values(self) -> None:
        record = IdentityRecord(
            identity_id="u1",
            identity_name="bob",
            identity_type=IdentityType.HUMAN,
            provider="azure",
        )
        assert record.status == IdentityStatus.UNKNOWN
        assert record.mfa_enabled is False
        assert record.is_privileged is False
        assert record.attached_policies == []
        assert record.tags == {}
        assert record.raw_metadata == {}

    def test_full_record(self) -> None:
        record = IdentityRecord(
            identity_id="AIDA123456789",
            identity_name="deploy-bot",
            identity_type=IdentityType.SERVICE,
            provider="aws",
            status=IdentityStatus.ACTIVE,
            created_at="2023-01-15T10:00:00Z",
            last_activity_at="2025-01-10T08:00:00Z",
            mfa_enabled=False,
            attached_policies=["AdministratorAccess"],
            is_privileged=True,
            arn="arn:aws:iam::123456789012:user/deploy-bot",
            tags={"team": "platform"},
        )
        assert record.mfa_enabled is False
        assert record.is_privileged is True
        assert "AdministratorAccess" in record.attached_policies
        assert record.tags == {"team": "platform"}

    def test_json_serialization(self) -> None:
        record = IdentityRecord(
            identity_id="u1",
            identity_name="alice",
            identity_type=IdentityType.HUMAN,
            provider="gcp",
        )
        data = record.model_dump(mode="json")
        assert data["identity_type"] == "human"  # Enum serialized as string
        assert data["status"] == "unknown"

    def test_json_deserialization(self) -> None:
        data = {
            "identity_id": "sp_abc",
            "identity_name": "my-app",
            "identity_type": "service",
            "provider": "azure",
            "status": "active",
            "mfa_enabled": False,
        }
        record = IdentityRecord.model_validate(data)
        assert record.identity_type == IdentityType.SERVICE
        assert record.status == IdentityStatus.ACTIVE


# ---------------------------------------------------------------------------
# AuditFinding tests
# ---------------------------------------------------------------------------


class TestAuditFinding:
    def test_minimal_valid_finding(self) -> None:
        finding = AuditFinding(
            category=FindingCategory.EXCESSIVE_PERMISSIONS,
            severity=FindingSeverity.CRITICAL,
            provider="aws",
            identity_id="u1",
            identity_name="admin-user",
            title="AdministratorAccess attached",
            description="User has full admin access.",
            risk_score=1.0,
        )
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.risk_score == 1.0

    def test_finding_id_auto_generated(self) -> None:
        f1 = AuditFinding(
            category=FindingCategory.MFA_NOT_ENABLED,
            severity=FindingSeverity.HIGH,
            provider="aws",
            identity_id="u1",
            identity_name="alice",
            title="MFA not enabled",
            description="...",
            risk_score=0.65,
        )
        f2 = AuditFinding(
            category=FindingCategory.MFA_NOT_ENABLED,
            severity=FindingSeverity.HIGH,
            provider="aws",
            identity_id="u2",
            identity_name="bob",
            title="MFA not enabled",
            description="...",
            risk_score=0.65,
        )
        # Each finding should have a unique ID
        assert f1.finding_id != f2.finding_id

    def test_risk_score_bounds(self) -> None:
        with pytest.raises(Exception):
            AuditFinding(
                category=FindingCategory.INACTIVE_ACCOUNT,
                severity=FindingSeverity.MEDIUM,
                provider="aws",
                identity_id="u1",
                identity_name="alice",
                title="Inactive",
                description="...",
                risk_score=1.5,  # Invalid — above 1.0
            )

    def test_risk_score_lower_bound(self) -> None:
        with pytest.raises(Exception):
            AuditFinding(
                category=FindingCategory.INACTIVE_ACCOUNT,
                severity=FindingSeverity.MEDIUM,
                provider="aws",
                identity_id="u1",
                identity_name="alice",
                title="Inactive",
                description="...",
                risk_score=-0.1,  # Invalid — below 0.0
            )

    def test_detected_at_is_set_automatically(self) -> None:
        finding = AuditFinding(
            category=FindingCategory.ORPHANED_ACCOUNT,
            severity=FindingSeverity.LOW,
            provider="gcp",
            identity_id="sa@project.iam.gserviceaccount.com",
            identity_name="old-service-account",
            title="Orphaned service account",
            description="...",
            risk_score=0.3,
        )
        assert finding.detected_at is not None


# ---------------------------------------------------------------------------
# RiskScore tests
# ---------------------------------------------------------------------------


class TestRiskScore:
    def test_compute_overall_weighted_average(self) -> None:
        score = RiskScore(
            identity_id="u1",
            identity_name="alice",
            provider="aws",
            privilege_score=1.0,   # Critical
            inactivity_score=0.5,  # Medium
            mfa_score=0.65,        # High
        )
        result = score.compute_overall(
            privilege_weight=0.4,
            inactivity_weight=0.3,
            mfa_weight=0.3,
        )
        # 1.0*0.4 + 0.5*0.3 + 0.65*0.3 = 0.4 + 0.15 + 0.195 = 0.745
        assert abs(result.overall_score - 0.745) < 0.01

    def test_severity_mapping_critical(self) -> None:
        score = RiskScore(
            identity_id="u1",
            identity_name="admin",
            provider="aws",
            privilege_score=1.0,
            inactivity_score=1.0,
            mfa_score=1.0,
        )
        score.compute_overall()
        assert score.severity == FindingSeverity.CRITICAL

    def test_severity_mapping_informational(self) -> None:
        score = RiskScore(
            identity_id="u1",
            identity_name="readonly-user",
            provider="aws",
            privilege_score=0.0,
            inactivity_score=0.0,
            mfa_score=0.0,
        )
        score.compute_overall()
        assert score.severity == FindingSeverity.INFORMATIONAL

    def test_overall_score_capped_at_1_0(self) -> None:
        score = RiskScore(
            identity_id="u1",
            identity_name="admin",
            provider="aws",
            privilege_score=1.0,
            inactivity_score=1.0,
            mfa_score=1.0,
        )
        score.compute_overall(privilege_weight=0.5, inactivity_weight=0.5, mfa_weight=0.5)
        # Weights don't sum to 1.0 but score is bounded by input values
        assert score.overall_score <= 1.0

    def test_finding_ids_default_empty(self) -> None:
        score = RiskScore(
            identity_id="u1",
            identity_name="alice",
            provider="azure",
        )
        assert score.finding_ids == []

    def test_severity_enum_values(self) -> None:
        """Verify all severity enum values are valid strings."""
        for severity in FindingSeverity:
            assert isinstance(severity.value, str)
            assert len(severity.value) > 0
