"""
Tests for analyzers/permission_boundary/analyzer.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.permission_boundary.analyzer import (
    BoundaryFinding,
    BoundaryReport,
    BoundarySeverity,
    PermissionBoundaryAnalyzer,
    PrincipalBoundaryPosture,
    _count_allow_actions,
    _find_wildcard_sensitive_actions,
    _trust_enforces_boundary,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _user(
    arn: str = "arn:aws:iam::123456789012:user/alice",
    boundary_arn: str = "arn:aws:iam::123456789012:policy/BoundaryPolicy",
    boundary_doc: dict | None = None,
) -> dict:
    result = {
        "Arn": arn,
        "Type": "user",
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": boundary_arn,
        },
    }
    if boundary_doc is not None:
        result["PermissionsBoundaryDocument"] = boundary_doc
    return result


def _role(
    arn: str = "arn:aws:iam::123456789012:role/AppRole",
    boundary_arn: str = "arn:aws:iam::123456789012:policy/BoundaryPolicy",
    boundary_doc: dict | None = None,
    trust_doc: dict | None = None,
) -> dict:
    result = {
        "Arn": arn,
        "Type": "role",
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": boundary_arn,
        },
    }
    if boundary_doc is not None:
        result["PermissionsBoundaryDocument"] = boundary_doc
    if trust_doc is not None:
        result["AssumeRolePolicyDocument"] = trust_doc
    return result


def _no_boundary_user(arn: str = "arn:aws:iam::123456789012:user/bob") -> dict:
    return {"Arn": arn, "Type": "user"}


def _policy_doc(*actions: str, effect: str = "Allow") -> dict:
    return {"Statement": [{"Effect": effect, "Action": list(actions), "Resource": "*"}]}


KNOWN_ARNS: set[str] = {"arn:aws:iam::123456789012:policy/BoundaryPolicy"}


# ===========================================================================
# _find_wildcard_sensitive_actions
# ===========================================================================

class TestFindWildcardSensitiveActions:
    def test_star_action(self):
        doc = _policy_doc("*")
        assert "*" in _find_wildcard_sensitive_actions(doc)

    def test_iam_star(self):
        doc = _policy_doc("iam:*")
        assert "iam:*" in _find_wildcard_sensitive_actions(doc)

    def test_kms_star(self):
        doc = _policy_doc("kms:*")
        assert "kms:*" in _find_wildcard_sensitive_actions(doc)

    def test_non_sensitive_service_star_ignored(self):
        doc = _policy_doc("s3:*")
        result = _find_wildcard_sensitive_actions(doc)
        assert "s3:*" not in result

    def test_explicit_action_not_flagged(self):
        doc = _policy_doc("iam:ListRoles")
        assert not _find_wildcard_sensitive_actions(doc)

    def test_deny_statement_ignored(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}
        assert not _find_wildcard_sensitive_actions(doc)

    def test_case_insensitive(self):
        doc = _policy_doc("IAM:*")
        assert "iam:*" in _find_wildcard_sensitive_actions(doc)

    def test_string_action(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "sts:*", "Resource": "*"}]}
        assert "sts:*" in _find_wildcard_sensitive_actions(doc)


# ===========================================================================
# _count_allow_actions
# ===========================================================================

class TestCountAllowActions:
    def test_counts_explicit_actions(self):
        doc = _policy_doc("s3:GetObject", "s3:PutObject", "ec2:DescribeInstances")
        assert _count_allow_actions(doc) == 3

    def test_wildcard_not_counted(self):
        doc = _policy_doc("*")
        assert _count_allow_actions(doc) == 0

    def test_service_wildcard_not_counted(self):
        doc = _policy_doc("iam:*")
        assert _count_allow_actions(doc) == 0

    def test_deny_not_counted(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}]}
        assert _count_allow_actions(doc) == 0

    def test_mixed_statements(self):
        doc = {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"},
                {"Effect": "Deny",  "Action": ["iam:DeleteUser"],               "Resource": "*"},
            ]
        }
        assert _count_allow_actions(doc) == 2

    def test_deduplicates_actions(self):
        doc = _policy_doc("s3:GetObject", "s3:getobject")  # same action, different case
        assert _count_allow_actions(doc) == 1


# ===========================================================================
# _trust_enforces_boundary
# ===========================================================================

class TestTrustEnforcesBoundary:
    def test_no_condition_returns_false(self):
        trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
        assert not _trust_enforces_boundary(trust)

    def test_condition_with_boundary_returns_true(self):
        trust = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::123:policy/X"}},
            }]
        }
        assert _trust_enforces_boundary(trust)

    def test_condition_without_boundary_returns_false(self):
        trust = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }]
        }
        assert not _trust_enforces_boundary(trust)

    def test_empty_statements(self):
        assert not _trust_enforces_boundary({"Statement": []})


# ===========================================================================
# PB-001: No boundary
# ===========================================================================

class TestPB001:
    def test_pb001_fires_for_user_without_boundary(self):
        analyzer = PermissionBoundaryAnalyzer()
        posture = analyzer.analyze_principal(_no_boundary_user())
        assert any(f.check_id == "PB-001" for f in posture.findings)

    def test_pb001_is_high(self):
        analyzer = PermissionBoundaryAnalyzer()
        posture = analyzer.analyze_principal(_no_boundary_user())
        f = next(f for f in posture.findings if f.check_id == "PB-001")
        assert f.severity == BoundarySeverity.HIGH

    def test_pb001_not_fired_when_boundary_present(self):
        analyzer = PermissionBoundaryAnalyzer()
        posture = analyzer.analyze_principal(_user())
        assert not any(f.check_id == "PB-001" for f in posture.findings)

    def test_pb001_suppressed_when_require_boundary_false(self):
        analyzer = PermissionBoundaryAnalyzer(require_boundary_on_all=False)
        posture = analyzer.analyze_principal(_no_boundary_user())
        assert not any(f.check_id == "PB-001" for f in posture.findings)

    def test_aws_managed_principal_skipped(self):
        analyzer = PermissionBoundaryAnalyzer(ignore_aws_managed=True)
        principal = {"Arn": "arn:aws:iam::aws:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS", "Type": "role"}
        posture = analyzer.analyze_principal(principal)
        assert posture.finding_count == 0


# ===========================================================================
# PB-002: Wildcard sensitive actions
# ===========================================================================

class TestPB002:
    def test_pb002_fires_for_iam_star(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_doc=_policy_doc("iam:*"))
        posture = analyzer.analyze_principal(principal)
        assert any(f.check_id == "PB-002" for f in posture.findings)

    def test_pb002_is_critical(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_doc=_policy_doc("sts:*"))
        posture = analyzer.analyze_principal(principal)
        f = next(f for f in posture.findings if f.check_id == "PB-002")
        assert f.severity == BoundarySeverity.CRITICAL

    def test_pb002_fires_for_global_star(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_doc=_policy_doc("*"))
        posture = analyzer.analyze_principal(principal)
        assert any(f.check_id == "PB-002" for f in posture.findings)

    def test_pb002_not_fired_for_non_sensitive_wildcard(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_doc=_policy_doc("s3:GetObject", "ec2:Describe*"))
        posture = analyzer.analyze_principal(principal)
        assert not any(f.check_id == "PB-002" for f in posture.findings)

    def test_pb002_not_fired_without_boundary_doc(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user()  # no boundary_doc
        posture = analyzer.analyze_principal(principal)
        assert not any(f.check_id == "PB-002" for f in posture.findings)


# ===========================================================================
# PB-003: Trust policy not enforcing boundary
# ===========================================================================

class TestPB003:
    def test_pb003_fires_for_role_without_boundary_condition(self):
        analyzer = PermissionBoundaryAnalyzer()
        trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
        principal = _role(trust_doc=trust)
        posture = analyzer.analyze_principal(principal)
        assert any(f.check_id == "PB-003" for f in posture.findings)

    def test_pb003_is_medium(self):
        analyzer = PermissionBoundaryAnalyzer()
        trust = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]}
        principal = _role(trust_doc=trust)
        posture = analyzer.analyze_principal(principal)
        f = next(f for f in posture.findings if f.check_id == "PB-003")
        assert f.severity == BoundarySeverity.MEDIUM

    def test_pb003_not_fired_when_trust_enforces_boundary(self):
        analyzer = PermissionBoundaryAnalyzer()
        trust = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::123:policy/B"}},
            }]
        }
        principal = _role(trust_doc=trust)
        posture = analyzer.analyze_principal(principal)
        assert not any(f.check_id == "PB-003" for f in posture.findings)

    def test_pb003_not_fired_for_users(self):
        """PB-003 only applies to roles."""
        analyzer = PermissionBoundaryAnalyzer()
        trust = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]}
        principal = _user()
        principal["AssumeRolePolicyDocument"] = trust
        posture = analyzer.analyze_principal(principal)
        assert not any(f.check_id == "PB-003" for f in posture.findings)

    def test_pb003_not_fired_without_trust_doc(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _role()  # no trust_doc
        posture = analyzer.analyze_principal(principal)
        assert not any(f.check_id == "PB-003" for f in posture.findings)


# ===========================================================================
# PB-004: Non-existent policy
# ===========================================================================

class TestPB004:
    def test_pb004_fires_for_unknown_boundary_arn(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_arn="arn:aws:iam::123456789012:policy/DeletedPolicy")
        posture = analyzer.analyze_principal(principal, known_policy_arns=KNOWN_ARNS)
        assert any(f.check_id == "PB-004" for f in posture.findings)

    def test_pb004_is_high(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_arn="arn:aws:iam::123456789012:policy/DeletedPolicy")
        posture = analyzer.analyze_principal(principal, known_policy_arns=KNOWN_ARNS)
        f = next(f for f in posture.findings if f.check_id == "PB-004")
        assert f.severity == BoundarySeverity.HIGH

    def test_pb004_not_fired_when_arn_is_known(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user()  # boundary_arn is in KNOWN_ARNS by default
        posture = analyzer.analyze_principal(principal, known_policy_arns=KNOWN_ARNS)
        assert not any(f.check_id == "PB-004" for f in posture.findings)

    def test_pb004_not_fired_when_known_arns_not_provided(self):
        """Without known_policy_arns, the check is skipped."""
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_arn="arn:aws:iam::123456789012:policy/MaybeDeleted")
        posture = analyzer.analyze_principal(principal, known_policy_arns=None)
        assert not any(f.check_id == "PB-004" for f in posture.findings)


# ===========================================================================
# PB-005: Overly permissive boundary
# ===========================================================================

class TestPB005:
    def test_pb005_fires_when_too_many_actions(self):
        analyzer = PermissionBoundaryAnalyzer()
        # 26 distinct explicit actions
        actions = [f"s3:Action{i}" for i in range(26)]
        principal = _user(boundary_doc=_policy_doc(*actions))
        posture = analyzer.analyze_principal(principal)
        assert any(f.check_id == "PB-005" for f in posture.findings)

    def test_pb005_is_medium(self):
        analyzer = PermissionBoundaryAnalyzer()
        actions = [f"s3:Action{i}" for i in range(26)]
        principal = _user(boundary_doc=_policy_doc(*actions))
        posture = analyzer.analyze_principal(principal)
        f = next(f for f in posture.findings if f.check_id == "PB-005")
        assert f.severity == BoundarySeverity.MEDIUM

    def test_pb005_not_fired_at_limit(self):
        analyzer = PermissionBoundaryAnalyzer()
        actions = [f"s3:Action{i}" for i in range(25)]  # exactly 25 — boundary
        principal = _user(boundary_doc=_policy_doc(*actions))
        posture = analyzer.analyze_principal(principal)
        assert not any(f.check_id == "PB-005" for f in posture.findings)


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_no_findings_zero_score(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user()
        posture = analyzer.analyze_principal(principal, known_policy_arns=KNOWN_ARNS)
        assert posture.risk_score == 0

    def test_pb001_only_score_is_20(self):
        analyzer = PermissionBoundaryAnalyzer()
        posture = analyzer.analyze_principal(_no_boundary_user())
        assert posture.risk_score == 20

    def test_pb002_only_score_is_35(self):
        analyzer = PermissionBoundaryAnalyzer()
        principal = _user(boundary_doc=_policy_doc("iam:*"))
        posture = analyzer.analyze_principal(principal, known_policy_arns=KNOWN_ARNS)
        assert posture.risk_score == 35

    def test_risk_score_capped_at_100(self):
        analyzer = PermissionBoundaryAnalyzer()
        # Trigger multiple checks via a deleted policy (PB-004=25) + many actions (PB-005=10)
        actions = [f"s3:Action{i}" for i in range(30)]
        principal = _user(
            boundary_arn="arn:aws:iam::123456789012:policy/Deleted",
            boundary_doc=_policy_doc(*actions),
        )
        posture = analyzer.analyze_principal(principal, known_policy_arns=KNOWN_ARNS)
        assert posture.risk_score <= 100


# ===========================================================================
# BoundaryPosture helpers
# ===========================================================================

class TestPrincipalBoundaryPosture:
    def _posture(self) -> PrincipalBoundaryPosture:
        f1 = BoundaryFinding("PB-001", BoundarySeverity.HIGH,     "t", "d", "r", "arn", "user")
        f2 = BoundaryFinding("PB-002", BoundarySeverity.CRITICAL, "t", "d", "r", "arn", "user")
        return PrincipalBoundaryPosture(
            principal_arn="arn:aws:iam::123:user/alice",
            principal_type="user",
            boundary_arn="",
            findings=[f1, f2],
            risk_score=55,
        )

    def test_finding_count(self):
        assert self._posture().finding_count == 2

    def test_critical_count(self):
        assert self._posture().critical_count == 1

    def test_posture_summary_contains_arn(self):
        assert "alice" in self._posture().posture_summary()

    def test_to_dict_keys(self):
        d = self._posture().to_dict()
        for k in ("principal_arn", "principal_type", "boundary_arn", "risk_score", "findings"):
            assert k in d


# ===========================================================================
# BoundaryReport
# ===========================================================================

class TestBoundaryReport:
    def _report(self) -> BoundaryReport:
        f1 = BoundaryFinding("PB-001", BoundarySeverity.HIGH,     "t", "d", "r", "a1", "user")
        f2 = BoundaryFinding("PB-002", BoundarySeverity.CRITICAL, "t", "d", "r", "a2", "role")
        p1 = PrincipalBoundaryPosture("a1", "user",  "", [f1], 20)
        p2 = PrincipalBoundaryPosture("a2", "role",  "arn", [f2], 35)
        return BoundaryReport(
            postures=[p1, p2],
            total_principals=2,
            unprotected_count=1,
            all_findings=[f1, f2],
        )

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_findings_by_check(self):
        assert len(self._report().findings_by_check("PB-001")) == 1

    def test_findings_by_severity(self):
        assert len(self._report().findings_by_severity(BoundarySeverity.HIGH)) == 1

    def test_summary_contains_counts(self):
        s = self._report().summary()
        assert "2" in s

    def test_empty_report(self):
        r = BoundaryReport()
        assert r.total_findings == 0


# ===========================================================================
# analyze() integration
# ===========================================================================

class TestAnalyzeIntegration:
    def test_analyze_returns_report(self):
        analyzer = PermissionBoundaryAnalyzer()
        report = analyzer.analyze([_user(), _no_boundary_user()])
        assert report.total_principals == 2

    def test_analyze_unprotected_count(self):
        analyzer = PermissionBoundaryAnalyzer()
        report = analyzer.analyze([_user(), _no_boundary_user()])
        assert report.unprotected_count == 1

    def test_analyze_empty_list(self):
        analyzer = PermissionBoundaryAnalyzer()
        report = analyzer.analyze([])
        assert report.total_principals == 0
        assert report.total_findings == 0

    def test_analyze_with_known_policy_arns(self):
        analyzer = PermissionBoundaryAnalyzer()
        principals = [
            _user(boundary_arn="arn:aws:iam::123456789012:policy/BoundaryPolicy"),
            _user(arn="arn:aws:iam::123456789012:user/carol",
                  boundary_arn="arn:aws:iam::123456789012:policy/Deleted"),
        ]
        report = analyzer.analyze(principals, known_policy_arns=KNOWN_ARNS)
        pb004_findings = report.findings_by_check("PB-004")
        assert len(pb004_findings) == 1
        assert "carol" in pb004_findings[0].principal_arn

    def test_finding_principal_arn_propagated(self):
        analyzer = PermissionBoundaryAnalyzer()
        arn = "arn:aws:iam::123456789012:user/dave"
        posture = analyzer.analyze_principal(_no_boundary_user(arn))
        assert posture.findings[0].principal_arn == arn

    def test_finding_principal_type_propagated(self):
        analyzer = PermissionBoundaryAnalyzer()
        posture = analyzer.analyze_principal(_no_boundary_user())
        assert posture.findings[0].principal_type == "user"
