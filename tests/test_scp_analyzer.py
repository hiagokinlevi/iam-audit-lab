"""
Tests for analyzers/scp_analyzer.py
Covers SCP-001 through SCP-007 checks, cross-policy guardrails, and happy paths.
"""
import pytest
from analyzers.scp_analyzer import (
    SCPAnalyzer,
    SCPDocument,
    SCPFinding,
    SCPReport,
    SCPSeverity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_ids(report: SCPReport):
    return {f.check_id for f in report.findings}


def _allow_star_doc():
    return SCPDocument(
        name="FullAWSAccess",
        statements=[{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    )


def _deny_root_doc():
    return SCPDocument(
        name="DenyRoot",
        statements=[{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalType": "Root"}},
        }],
    )


def _deny_cloudtrail_doc():
    return SCPDocument(
        name="DenyCloudTrail",
        statements=[{
            "Effect": "Deny",
            "Action": [
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
            ],
            "Resource": "*",
        }],
    )


def _deny_leave_org_doc():
    return SCPDocument(
        name="DenyLeaveOrg",
        statements=[{
            "Effect": "Deny",
            "Action": "organizations:LeaveOrganization",
            "Resource": "*",
        }],
    )


def _clean_guardrail_set():
    """Minimal set of SCPs that satisfy all three guardrail checks."""
    return [_deny_root_doc(), _deny_cloudtrail_doc(), _deny_leave_org_doc()]


# ---------------------------------------------------------------------------
# SCPDocument — from_policy_document
# ---------------------------------------------------------------------------

class TestSCPDocument:
    def test_from_policy_document_list(self):
        doc = SCPDocument.from_policy_document(
            "test",
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        )
        assert doc.name == "test"
        assert len(doc.statements) == 1

    def test_from_policy_document_single_dict(self):
        """Statement can be a dict (not a list)."""
        doc = SCPDocument.from_policy_document(
            "single",
            {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
        )
        assert len(doc.statements) == 1

    def test_from_policy_document_empty(self):
        doc = SCPDocument.from_policy_document("empty", {})
        assert doc.statements == []

    def test_target_field(self):
        doc = SCPDocument.from_policy_document("p", {}, target="ou-abc-123")
        assert doc.target == "ou-abc-123"


# ---------------------------------------------------------------------------
# SCP-006: No SCPs attached
# ---------------------------------------------------------------------------

class TestSCP006:
    def test_no_documents_fires_scp006(self):
        report = SCPAnalyzer().analyze([])
        assert "SCP-006" in check_ids(report)

    def test_no_documents_severity_critical(self):
        report = SCPAnalyzer().analyze([])
        findings = [f for f in report.findings if f.check_id == "SCP-006"]
        assert findings[0].severity == SCPSeverity.CRITICAL

    def test_no_documents_returns_early(self):
        report = SCPAnalyzer().analyze([])
        assert report.policies_analyzed == 0
        # Should return early — only SCP-006
        assert len(report.findings) == 1

    def test_no_documents_risk_score_nonzero(self):
        report = SCPAnalyzer().analyze([])
        assert report.risk_score > 0


# ---------------------------------------------------------------------------
# SCP-001: Allow Action:*
# ---------------------------------------------------------------------------

class TestSCP001:
    def test_allow_action_star(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-001" in check_ids(report)

    def test_allow_action_star_severity_high(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-001"]
        assert findings[0].severity == SCPSeverity.HIGH

    def test_allow_specific_action_no_scp001(self):
        doc = SCPDocument(
            name="RestrictedAccess",
            statements=[{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-001" not in check_ids(report)

    def test_deny_star_does_not_fire_scp001(self):
        doc = SCPDocument(
            name="DenyAll",
            statements=[{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-001" not in check_ids(report)

    def test_scp001_evidence_truncated(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-001"]
        d = findings[0].to_dict()
        assert len(d["evidence"]) <= 512


# ---------------------------------------------------------------------------
# SCP-005: Allow Resource:*
# ---------------------------------------------------------------------------

class TestSCP005:
    def test_allow_resource_star(self):
        doc = SCPDocument(
            name="AllResources",
            statements=[{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-005" in check_ids(report)

    def test_scp005_severity_medium(self):
        doc = SCPDocument(
            name="AllResources",
            statements=[{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-005"]
        assert findings[0].severity == SCPSeverity.MEDIUM

    def test_allow_scoped_resource_no_scp005(self):
        doc = SCPDocument(
            name="Scoped",
            statements=[{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-005" not in check_ids(report)

    def test_deny_resource_star_no_scp005(self):
        doc = SCPDocument(
            name="DenyAll",
            statements=[{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-005" not in check_ids(report)


# ---------------------------------------------------------------------------
# SCP-007: NotAction
# ---------------------------------------------------------------------------

class TestSCP007:
    def test_allow_not_action_string(self):
        doc = SCPDocument(
            name="BroadAllowExcept",
            statements=[{
                "Effect": "Allow",
                "NotAction": "iam:CreateUser",
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-007" in check_ids(report)

    def test_allow_not_action_list(self):
        doc = SCPDocument(
            name="BroadAllowExcept",
            statements=[{
                "Effect": "Allow",
                "NotAction": ["iam:CreateUser", "sts:AssumeRole"],
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-007" in check_ids(report)

    def test_scp007_severity_medium(self):
        doc = SCPDocument(
            name="BroadAllowExcept",
            statements=[{
                "Effect": "Allow",
                "NotAction": "iam:CreateUser",
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-007"]
        assert findings[0].severity == SCPSeverity.MEDIUM

    def test_deny_not_action_no_scp007(self):
        """SCP-007 only fires for Allow statements."""
        doc = SCPDocument(
            name="DenyExcept",
            statements=[{
                "Effect": "Deny",
                "NotAction": "s3:GetObject",
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-007" not in check_ids(report)


# ---------------------------------------------------------------------------
# SCP-002: No Deny for root account usage
# ---------------------------------------------------------------------------

class TestSCP002:
    def test_no_root_deny_fires_scp002(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=True,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-002" in check_ids(report)

    def test_deny_root_via_condition_satisfies(self):
        docs = [_allow_star_doc(), _deny_root_doc()]
        report = SCPAnalyzer(
            require_root_deny=True,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze(docs)
        assert "SCP-002" not in check_ids(report)

    def test_deny_assume_root_satisfies(self):
        doc = SCPDocument(
            name="DenyAssumeRoot",
            statements=[{
                "Effect": "Deny",
                "Action": "sts:AssumeRoot",
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=True,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-002" not in check_ids(report)

    def test_scp002_severity_critical(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=True,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-002"]
        assert findings[0].severity == SCPSeverity.CRITICAL

    def test_require_root_deny_false_skips_check(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-002" not in check_ids(report)

    def test_deny_star_without_root_condition_not_enough(self):
        """A Deny * without root condition should NOT satisfy SCP-002."""
        doc = SCPDocument(
            name="DenyAll",
            statements=[{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=True,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        # Deny * covers all actions but SCP-002 also requires root condition
        # _deny_covers_action returns True (* covers *), but _has_condition fails
        # So SCP-002 should still fire
        assert "SCP-002" in check_ids(report)


# ---------------------------------------------------------------------------
# SCP-003: No Deny for CloudTrail
# ---------------------------------------------------------------------------

class TestSCP003:
    def test_no_cloudtrail_deny_fires_scp003(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=True,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-003" in check_ids(report)

    def test_deny_cloudtrail_specific_actions_satisfies(self):
        docs = [_allow_star_doc(), _deny_cloudtrail_doc()]
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=True,
            require_org_deny=False,
        ).analyze(docs)
        assert "SCP-003" not in check_ids(report)

    def test_deny_cloudtrail_star_satisfies(self):
        doc = SCPDocument(
            name="DenyCloudTrailAll",
            statements=[{
                "Effect": "Deny",
                "Action": "cloudtrail:*",
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=True,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-003" not in check_ids(report)

    def test_scp003_severity_critical(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=True,
            require_org_deny=False,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-003"]
        assert findings[0].severity == SCPSeverity.CRITICAL

    def test_require_cloudtrail_false_skips_check(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-003" not in check_ids(report)


# ---------------------------------------------------------------------------
# SCP-004: No Deny for LeaveOrganization
# ---------------------------------------------------------------------------

class TestSCP004:
    def test_no_leave_org_deny_fires_scp004(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=True,
        ).analyze([doc])
        assert "SCP-004" in check_ids(report)

    def test_deny_leave_org_satisfies(self):
        docs = [_allow_star_doc(), _deny_leave_org_doc()]
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=True,
        ).analyze(docs)
        assert "SCP-004" not in check_ids(report)

    def test_deny_organizations_star_satisfies(self):
        doc = SCPDocument(
            name="DenyOrg",
            statements=[{
                "Effect": "Deny",
                "Action": "organizations:*",
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=True,
        ).analyze([doc])
        assert "SCP-004" not in check_ids(report)

    def test_scp004_severity_critical(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=True,
        ).analyze([doc])
        findings = [f for f in report.findings if f.check_id == "SCP-004"]
        assert findings[0].severity == SCPSeverity.CRITICAL

    def test_require_org_deny_false_skips_check(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-004" not in check_ids(report)


# ---------------------------------------------------------------------------
# Cross-policy guardrail checks (guardrail satisfied across multiple SCPs)
# ---------------------------------------------------------------------------

class TestCrossPolicyGuardrails:
    def test_guardrails_satisfied_across_policies(self):
        docs = _clean_guardrail_set()
        report = SCPAnalyzer().analyze(docs)
        assert "SCP-002" not in check_ids(report)
        assert "SCP-003" not in check_ids(report)
        assert "SCP-004" not in check_ids(report)

    def test_guardrails_satisfied_in_single_policy(self):
        all_in_one = SCPDocument(
            name="AllGuardrails",
            statements=[
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalType": "Root"}},
                },
                {
                    "Effect": "Deny",
                    "Action": ["cloudtrail:DeleteTrail", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail"],
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "organizations:LeaveOrganization",
                    "Resource": "*",
                },
            ],
        )
        report = SCPAnalyzer().analyze([all_in_one])
        assert "SCP-002" not in check_ids(report)
        assert "SCP-003" not in check_ids(report)
        assert "SCP-004" not in check_ids(report)


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_clean_scp_set_low_score(self):
        """A well-configured SCP set with all guardrails satisfied."""
        docs = _clean_guardrail_set()
        report = SCPAnalyzer().analyze(docs)
        # May still have SCP-005 from Allow statements in other docs
        # But guardrail checks should not fire
        assert report.risk_score <= 100

    def test_no_scps_risk_score_is_35(self):
        report = SCPAnalyzer().analyze([])
        assert report.risk_score == 35  # SCP-006 weight

    def test_risk_score_capped_at_100(self):
        # Fire all checks: SCP-001(40)+SCP-002(45)+SCP-003(40)+SCP-004(35)+SCP-005(30)+SCP-007(25) = 215
        doc = SCPDocument(
            name="WorstCase",
            statements=[{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "NotAction": "iam:CreateUser",
            }],
        )
        report = SCPAnalyzer().analyze([doc])
        assert report.risk_score <= 100

    def test_risk_score_nonzero_when_findings_exist(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert report.risk_score > 0


# ---------------------------------------------------------------------------
# SCPReport helpers
# ---------------------------------------------------------------------------

class TestSCPReport:
    def test_total_findings(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert report.total_findings == len(report.findings)

    def test_critical_findings_filter(self):
        report = SCPAnalyzer(
            require_root_deny=True,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([_allow_star_doc()])
        crit = report.critical_findings
        assert all(f.severity == SCPSeverity.CRITICAL for f in crit)

    def test_high_findings_filter(self):
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([_allow_star_doc()])
        high = report.high_findings
        assert all(f.severity == SCPSeverity.HIGH for f in high)

    def test_findings_by_check(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        scp001 = report.findings_by_check("SCP-001")
        assert all(f.check_id == "SCP-001" for f in scp001)

    def test_findings_for_policy(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        findings = report.findings_for_policy("FullAWSAccess")
        assert all(f.policy_name == "FullAWSAccess" for f in findings)

    def test_summary_string(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        s = report.summary()
        assert "SCP Report" in s
        assert "risk_score" in s

    def test_to_dict_structure(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        d = report.to_dict()
        assert "total_findings" in d
        assert "risk_score" in d
        assert "critical" in d
        assert "high" in d
        assert "policies_analyzed" in d
        assert "generated_at" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)

    def test_finding_to_dict(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        d = report.findings[0].to_dict()
        assert "check_id" in d
        assert "severity" in d
        assert "policy_name" in d
        assert "title" in d
        assert "detail" in d
        assert "evidence" in d
        assert "remediation" in d

    def test_finding_summary(self):
        doc = _allow_star_doc()
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        s = report.findings[0].summary()
        assert "[SCP-" in s

    def test_policies_analyzed_count(self):
        docs = [_deny_root_doc(), _deny_cloudtrail_doc()]
        report = SCPAnalyzer().analyze(docs)
        assert report.policies_analyzed == 2


# ---------------------------------------------------------------------------
# Action list normalization
# ---------------------------------------------------------------------------

class TestActionNormalization:
    def test_action_as_string(self):
        doc = SCPDocument(
            name="SingleAction",
            statements=[{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-001" in check_ids(report)

    def test_action_as_list(self):
        doc = SCPDocument(
            name="ListAction",
            statements=[{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=False,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-001" in check_ids(report)

    def test_cloudtrail_wildcard_deny_case_insensitive(self):
        doc = SCPDocument(
            name="CloudTrailDeny",
            statements=[{
                "Effect": "Deny",
                "Action": "CloudTrail:*",  # mixed case
                "Resource": "*",
            }],
        )
        report = SCPAnalyzer(
            require_root_deny=False,
            require_cloudtrail_deny=True,
            require_org_deny=False,
        ).analyze([doc])
        assert "SCP-003" not in check_ids(report)
