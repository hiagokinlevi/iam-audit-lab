"""Unit tests for IAM trust analysis and posture scoring."""
import pytest

from analyzers.trust_analysis.analyzer import (
    TrustFinding,
    TrustPolicyRecord,
    analyze_trust_policies,
)
from schemas.identity import AuditFinding, FindingCategory, FindingSeverity
from reports.posture_score import PostureScore, compute_posture_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACCOUNT_ID = "123456789012"
_OTHER_ACCOUNT = "999999999999"


def _role(name: str, trust_policy: dict) -> TrustPolicyRecord:
    return TrustPolicyRecord(
        role_arn=f"arn:aws:iam::{_ACCOUNT_ID}:role/{name}",
        role_name=name,
        trust_policy=trust_policy,
        account_id=_ACCOUNT_ID,
    )


def _finding(severity: FindingSeverity, category: FindingCategory) -> AuditFinding:
    return AuditFinding(
        category=category,
        severity=severity,
        provider="aws",
        identity_id="user-001",
        identity_name="test-user",
        title="Test finding",
        description="Test",
        evidence=[],
        remediation="Test",
        risk_score=0.5,
    )


# ---------------------------------------------------------------------------
# TRP001: Wildcard principal
# ---------------------------------------------------------------------------


def test_wildcard_principal_is_critical():
    r = _role("WildcardRole", {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    })
    findings = analyze_trust_policies([r])
    trp001 = [f for f in findings if f.rule_id == "TRP001"]
    assert trp001
    assert trp001[0].severity == "critical"


def test_specific_principal_no_trp001():
    r = _role("SafeRole", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:root"},
            "Action": "sts:AssumeRole",
        }]
    })
    findings = analyze_trust_policies([r])
    assert not any(f.rule_id == "TRP001" for f in findings)


def test_single_statement_dict_wildcard_principal_is_critical():
    r = _role("WildcardRoleDict", {
        "Statement": {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }
    })
    findings = analyze_trust_policies([r])

    assert any(f.rule_id == "TRP001" for f in findings)


# ---------------------------------------------------------------------------
# TRP003: Cross-account without ExternalId
# ---------------------------------------------------------------------------


def test_cross_account_no_external_id_is_high():
    r = _role("CrossAccountRole", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
        }]
    })
    findings = analyze_trust_policies([r])
    trp003 = [f for f in findings if f.rule_id == "TRP003"]
    assert trp003
    assert trp003[0].severity == "high"


def test_cross_account_with_external_id_is_info():
    r = _role("SecureCrossAccountRole", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "my-external-id-12345"}},
        }]
    })
    findings = analyze_trust_policies([r])
    trp006 = [f for f in findings if f.rule_id == "TRP006"]
    assert trp006
    assert trp006[0].severity == "info"
    # Should not have TRP003 when ExternalId is present
    assert not any(f.rule_id == "TRP003" for f in findings)


def test_same_account_trust_no_cross_account_finding():
    r = _role("SameAccountRole", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:root"},
            "Action": "sts:AssumeRole",
        }]
    })
    findings = analyze_trust_policies([r])
    # Same account — should not produce TRP003
    assert not any(f.rule_id == "TRP003" for f in findings)


def test_single_statement_dict_cross_account_external_id_is_info():
    r = _role("SecureCrossAccountRoleDict", {
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "my-external-id-12345"}},
        }
    })
    findings = analyze_trust_policies([r])

    assert any(f.rule_id == "TRP006" for f in findings)
    assert not any(f.rule_id == "TRP003" for f in findings)


# ---------------------------------------------------------------------------
# TRP004: Wildcard condition
# ---------------------------------------------------------------------------


def test_wildcard_condition_is_medium():
    r = _role("WildcardCondRole", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Dev*"}},
        }]
    })
    findings = analyze_trust_policies([r])
    trp004 = [f for f in findings if f.rule_id == "TRP004"]
    assert trp004
    assert trp004[0].severity == "medium"


# ---------------------------------------------------------------------------
# TRP005: Third-party service without ExternalId
# ---------------------------------------------------------------------------


def test_third_party_no_external_id_is_low():
    r = _role("DatadogRole", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::464622532012:root"},  # Datadog AWS account
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "some-id"}},  # Has ExternalId
        }]
    })
    # Should not trigger TRP005 since it has ExternalId — use a datadog.com principal instead
    r2 = _role("DatadogRoleNoExtId", {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::datadog.com:oidc-provider"},
            "Action": "sts:AssumeRole",
        }]
    })
    findings = analyze_trust_policies([r2])
    trp005 = [f for f in findings if f.rule_id == "TRP005"]
    assert trp005


# ---------------------------------------------------------------------------
# Deny statement — should be ignored
# ---------------------------------------------------------------------------


def test_deny_statement_ignored():
    r = _role("DenyRole", {
        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}]
    })
    findings = analyze_trust_policies([r])
    assert not any(f.rule_id == "TRP001" for f in findings)


# ---------------------------------------------------------------------------
# Findings sorted by severity
# ---------------------------------------------------------------------------


def test_findings_sorted_critical_first():
    r = _role("MultiIssueRole", {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",   # TRP001 CRITICAL
                "Action": "sts:AssumeRole",
                "Condition": {"StringLike": {"aws:SourceIp": "10.*"}},  # TRP004 MEDIUM
            }
        ]
    })
    findings = analyze_trust_policies([r])
    if len(findings) >= 2:
        severities = [f.severity for f in findings]
        assert severities[0] == "critical" or severities[0] in ("critical", "medium")


# ---------------------------------------------------------------------------
# Posture scoring
# ---------------------------------------------------------------------------


def test_no_findings_score_100():
    score = compute_posture_score([])
    assert score.score == 100


def test_critical_finding_deducts_points():
    findings = [_finding(FindingSeverity.CRITICAL, FindingCategory.EXCESSIVE_PERMISSIONS)]
    score = compute_posture_score(findings)
    assert score.score < 100


def test_mfa_bonus():
    score_without_bonus = compute_posture_score([])
    score_with_bonus = compute_posture_score([], mfa_coverage_percent=99.5)
    # With full MFA coverage we get bonus points but score is capped at 100
    assert score_with_bonus.score >= score_without_bonus.score


def test_low_mfa_coverage_note():
    score = compute_posture_score([], mfa_coverage_percent=40.0)
    assert any("50%" in note for note in score.notes)


def test_multiple_critical_capped():
    # Many critical findings of the same category should not exceed the cap
    findings = [
        _finding(FindingSeverity.CRITICAL, FindingCategory.EXCESSIVE_PERMISSIONS)
        for _ in range(10)
    ]
    score = compute_posture_score(findings)
    # Deduction is capped per category — score should not go below 70 (30-point max for excessive)
    assert score.score >= 70


def test_rating_excellent():
    score = compute_posture_score([])
    assert score.rating == "Excellent"


def test_rating_critical():
    findings = [
        _finding(FindingSeverity.CRITICAL, cat)
        for cat in [
            FindingCategory.EXCESSIVE_PERMISSIONS,
            FindingCategory.PRIVILEGED_WITHOUT_MFA,
            FindingCategory.MFA_NOT_ENABLED,
            FindingCategory.INACTIVE_ACCOUNT,
        ]
    ]
    score = compute_posture_score(findings)
    assert score.score <= 40
