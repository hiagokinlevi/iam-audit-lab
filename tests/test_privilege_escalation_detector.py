# test_privilege_escalation_detector.py
# 90+ tests covering every check, edge case, and data-model method of
# privilege_escalation_detector.py.
#
# Copyright (c) 2026 Cyber Port (github.com/hiagokinlevi)
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See: https://creativecommons.org/licenses/by/4.0/

from __future__ import annotations

import sys
import os

# Ensure the analyzers package is importable when running from the project root
# or directly from the tests/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analyzers.privilege_escalation_detector import (
    IAMStatement,
    IAMPolicyDoc,
    IAMRole,
    PrivEscFinding,
    PrivEscResult,
    PrivilegeEscalationDetector,
    _CHECK_WEIGHTS,
    _has_action,
    _has_all_actions,
    _has_passrole_with_wildcard_resource,
)

# ---------------------------------------------------------------------------
# Factories / helpers
# ---------------------------------------------------------------------------

def _allow(actions: list, resources: list | None = None, conditions: dict | None = None) -> IAMStatement:
    """Build a minimal Allow statement."""
    return IAMStatement(
        effect="Allow",
        actions=actions,
        resources=resources if resources is not None else ["*"],
        conditions=conditions or {},
    )


def _deny(actions: list, resources: list | None = None) -> IAMStatement:
    """Build a minimal Deny statement."""
    return IAMStatement(
        effect="Deny",
        actions=actions,
        resources=resources if resources is not None else ["*"],
        conditions={},
    )


def _policy(name: str, *stmts: IAMStatement) -> IAMPolicyDoc:
    return IAMPolicyDoc(policy_name=name, statements=list(stmts))


def _role(name: str, *policies: IAMPolicyDoc) -> IAMRole:
    arn = f"arn:aws:iam::123456789012:role/{name}"
    return IAMRole(role_name=name, role_arn=arn, policies=list(policies))


def _detect(role: IAMRole) -> "PrivEscResult":
    return PrivilegeEscalationDetector().analyze(role)


def _find_by_id(result: "PrivEscResult", check_id: str) -> "PrivEscFinding | None":
    for f in result.findings:
        if f.check_id == check_id:
            return f
    return None


# ===========================================================================
# Section 1 — Helper function unit tests
# ===========================================================================

class TestHasAction:
    """Unit tests for the _has_action() helper."""

    def test_exact_match(self):
        stmts = [_allow(["iam:CreatePolicyVersion"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True

    def test_case_insensitive_action(self):
        stmts = [_allow(["IAM:CREATEPOLICYVERSION"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True

    def test_global_wildcard_covers_any_action(self):
        stmts = [_allow(["*"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True

    def test_service_wildcard_covers_service_action(self):
        stmts = [_allow(["iam:*"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True

    def test_service_wildcard_does_not_cover_other_service(self):
        stmts = [_allow(["iam:*"])]
        assert _has_action(stmts, "sts:AssumeRole") is False

    def test_lambda_wildcard_covers_lambda_create(self):
        stmts = [_allow(["lambda:*"])]
        assert _has_action(stmts, "lambda:CreateFunction") is True

    def test_deny_statement_ignored(self):
        stmts = [_deny(["iam:CreatePolicyVersion"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is False

    def test_empty_resource_list_not_counted(self):
        stmts = [_allow(["iam:CreatePolicyVersion"], resources=[])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is False

    def test_specific_resource_still_matches_action(self):
        stmts = [_allow(["iam:CreatePolicyVersion"], resources=["arn:aws:iam::*:policy/MyPolicy"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True

    def test_no_matching_action(self):
        stmts = [_allow(["iam:ListRoles"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is False

    def test_multiple_statements_one_matches(self):
        stmts = [_allow(["iam:ListRoles"]), _allow(["iam:CreatePolicyVersion"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True

    def test_empty_statements(self):
        assert _has_action([], "iam:CreatePolicyVersion") is False

    def test_allow_mixed_with_deny_allow_wins(self):
        # _has_action only checks Allow; Deny does not block here (by design).
        stmts = [
            _deny(["iam:CreatePolicyVersion"]),
            _allow(["iam:CreatePolicyVersion"]),
        ]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is True


class TestHasAllActions:
    """Unit tests for _has_all_actions()."""

    def test_all_present(self):
        stmts = [_allow(["iam:AttachRolePolicy", "sts:AssumeRole"])]
        assert _has_all_actions(stmts, ["iam:AttachRolePolicy", "sts:AssumeRole"]) is True

    def test_one_missing(self):
        stmts = [_allow(["iam:AttachRolePolicy"])]
        assert _has_all_actions(stmts, ["iam:AttachRolePolicy", "sts:AssumeRole"]) is False

    def test_empty_action_list_is_vacuously_true(self):
        stmts = [_allow(["iam:ListRoles"])]
        assert _has_all_actions(stmts, []) is True

    def test_wildcard_satisfies_all(self):
        stmts = [_allow(["*"])]
        assert _has_all_actions(stmts, ["iam:AttachRolePolicy", "sts:AssumeRole"]) is True


class TestHasPassroleWildcard:
    """Unit tests for _has_passrole_with_wildcard_resource()."""

    def test_passrole_with_star_resource(self):
        stmts = [_allow(["iam:PassRole"], resources=["*"])]
        assert _has_passrole_with_wildcard_resource(stmts) is True

    def test_passrole_with_specific_arn(self):
        stmts = [_allow(["iam:PassRole"], resources=["arn:aws:iam::123:role/SpecificRole"])]
        assert _has_passrole_with_wildcard_resource(stmts) is False

    def test_no_passrole(self):
        stmts = [_allow(["iam:ListRoles"], resources=["*"])]
        assert _has_passrole_with_wildcard_resource(stmts) is False

    def test_iam_star_wildcard_with_star_resource(self):
        # iam:* covers iam:PassRole; resource is "*" — should trigger
        stmts = [_allow(["iam:*"], resources=["*"])]
        assert _has_passrole_with_wildcard_resource(stmts) is True

    def test_global_wildcard_action_with_star_resource(self):
        stmts = [_allow(["*"], resources=["*"])]
        assert _has_passrole_with_wildcard_resource(stmts) is True

    def test_deny_passrole_not_counted(self):
        stmts = [_deny(["iam:PassRole"], resources=["*"])]
        assert _has_passrole_with_wildcard_resource(stmts) is False

    def test_empty_resource_not_counted(self):
        stmts = [_allow(["iam:PassRole"], resources=[])]
        assert _has_passrole_with_wildcard_resource(stmts) is False


# ===========================================================================
# Section 2 — Clean role (no dangerous permissions)
# ===========================================================================

class TestCleanRole:
    """A role with only safe read permissions should produce zero findings."""

    def test_no_findings_on_read_only_role(self):
        role = _role(
            "ReadOnly",
            _policy("ReadOnlyPolicy", _allow(["iam:ListRoles", "iam:GetRole", "s3:GetObject"])),
        )
        result = _detect(role)
        assert result.findings == []
        assert result.risk_score == 0

    def test_empty_policies_role(self):
        result = _detect(_role("EmptyRole"))
        assert result.findings == []
        assert result.risk_score == 0

    def test_empty_statements_policy(self):
        role = _role("NoStmts", _policy("Empty"))
        result = _detect(role)
        assert result.findings == []
        assert result.risk_score == 0

    def test_role_name_and_arn_preserved(self):
        role = _role("MyRole")
        result = _detect(role)
        assert result.role_name == "MyRole"
        assert result.role_arn == "arn:aws:iam::123456789012:role/MyRole"


# ===========================================================================
# Section 3 — PRIV-ESC-001 (iam:CreatePolicyVersion)
# ===========================================================================

class TestPrivEsc001:

    def test_exact_action_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_iam_star_wildcard_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_global_star_wildcard_triggers(self):
        role = _role("R", _policy("P", _allow(["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_other_iam_action_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:ListPolicies"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is None

    def test_deny_only_does_not_trigger(self):
        role = _role("R", _policy("P", _deny(["iam:CreatePolicyVersion"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is None

    def test_severity_is_critical(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert finding.severity == "CRITICAL"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert "iam:CreatePolicyVersion" in finding.dangerous_actions

    def test_risk_score_reflects_weight(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        result = _detect(role)
        assert result.risk_score == _CHECK_WEIGHTS["PRIV-ESC-001"]


# ===========================================================================
# Section 4 — PRIV-ESC-002 (iam:AttachRolePolicy + sts:AssumeRole)
# ===========================================================================

class TestPrivEsc002:

    def test_both_actions_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:AttachRolePolicy", "sts:AssumeRole"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is not None

    def test_only_attach_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:AttachRolePolicy"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is None

    def test_only_assume_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["sts:AssumeRole"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is None

    def test_actions_split_across_statements_triggers(self):
        role = _role(
            "R",
            _policy("P",
                _allow(["iam:AttachRolePolicy"]),
                _allow(["sts:AssumeRole"]),
            ),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is not None

    def test_actions_split_across_policies_triggers(self):
        role = _role(
            "R",
            _policy("P1", _allow(["iam:AttachRolePolicy"])),
            _policy("P2", _allow(["sts:AssumeRole"])),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is not None

    def test_severity_is_critical(self):
        role = _role("R", _policy("P", _allow(["iam:AttachRolePolicy", "sts:AssumeRole"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-002")
        assert finding.severity == "CRITICAL"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["iam:AttachRolePolicy", "sts:AssumeRole"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-002")
        assert "iam:AttachRolePolicy" in finding.dangerous_actions
        assert "sts:AssumeRole" in finding.dangerous_actions

    def test_iam_star_satisfies_both(self):
        # iam:* covers AttachRolePolicy; separately sts:AssumeRole must be explicit
        role = _role("R", _policy("P", _allow(["iam:*", "sts:AssumeRole"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is not None

    def test_global_star_satisfies_both(self):
        role = _role("R", _policy("P", _allow(["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is not None


# ===========================================================================
# Section 5 — PRIV-ESC-003 (iam:PassRole with resource "*")
# ===========================================================================

class TestPrivEsc003:

    def test_passrole_with_star_resource_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:PassRole"], resources=["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-003") is not None

    def test_passrole_with_specific_arn_does_not_trigger(self):
        role = _role(
            "R",
            _policy("P", _allow(["iam:PassRole"], resources=["arn:aws:iam::123:role/SomeRole"])),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-003") is None

    def test_no_passrole_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:ListRoles"], resources=["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-003") is None

    def test_iam_star_plus_star_resource_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:*"], resources=["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-003") is not None

    def test_global_star_action_plus_star_resource_triggers(self):
        role = _role("R", _policy("P", _allow(["*"], resources=["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-003") is not None

    def test_severity_is_critical(self):
        role = _role("R", _policy("P", _allow(["iam:PassRole"], resources=["*"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-003")
        assert finding.severity == "CRITICAL"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["iam:PassRole"], resources=["*"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-003")
        assert "iam:PassRole" in finding.dangerous_actions

    def test_passrole_empty_resource_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:PassRole"], resources=[])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-003") is None


# ===========================================================================
# Section 6 — PRIV-ESC-004 (iam:CreateLoginProfile)
# ===========================================================================

class TestPrivEsc004:

    def test_create_login_profile_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-004") is not None

    def test_update_login_profile_does_not_trigger_004(self):
        role = _role("R", _policy("P", _allow(["iam:UpdateLoginProfile"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-004") is None

    def test_severity_is_high(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-004")
        assert finding.severity == "HIGH"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-004")
        assert "iam:CreateLoginProfile" in finding.dangerous_actions

    def test_iam_star_triggers_004(self):
        role = _role("R", _policy("P", _allow(["iam:*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-004") is not None

    def test_unrelated_action_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:ListUsers"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-004") is None


# ===========================================================================
# Section 7 — PRIV-ESC-005 (iam:UpdateLoginProfile)
# ===========================================================================

class TestPrivEsc005:

    def test_update_login_profile_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:UpdateLoginProfile"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-005") is not None

    def test_create_login_profile_does_not_trigger_005(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-005") is None

    def test_severity_is_high(self):
        role = _role("R", _policy("P", _allow(["iam:UpdateLoginProfile"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-005")
        assert finding.severity == "HIGH"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["iam:UpdateLoginProfile"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-005")
        assert "iam:UpdateLoginProfile" in finding.dangerous_actions

    def test_iam_star_triggers_005(self):
        role = _role("R", _policy("P", _allow(["iam:*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-005") is not None

    def test_unrelated_action_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:GetLoginProfile"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-005") is None


# ===========================================================================
# Section 8 — PRIV-ESC-006 (lambda:CreateFunction + iam:PassRole)
# ===========================================================================

class TestPrivEsc006:

    def test_create_function_and_passrole_triggers(self):
        role = _role("R", _policy("P", _allow(["lambda:CreateFunction", "iam:PassRole"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-006") is not None

    def test_lambda_star_and_passrole_triggers(self):
        role = _role("R", _policy("P", _allow(["lambda:*", "iam:PassRole"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-006") is not None

    def test_only_create_function_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["lambda:CreateFunction"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-006") is None

    def test_only_passrole_does_not_trigger_006(self):
        # PassRole alone triggers PRIV-ESC-003 if resource is *, but not 006.
        role = _role("R", _policy("P", _allow(["iam:PassRole"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-006") is None

    def test_severity_is_critical(self):
        role = _role("R", _policy("P", _allow(["lambda:CreateFunction", "iam:PassRole"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-006")
        assert finding.severity == "CRITICAL"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["lambda:CreateFunction", "iam:PassRole"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-006")
        assert "lambda:CreateFunction" in finding.dangerous_actions
        assert "iam:PassRole" in finding.dangerous_actions

    def test_actions_across_policies_triggers(self):
        role = _role(
            "R",
            _policy("P1", _allow(["lambda:CreateFunction"])),
            _policy("P2", _allow(["iam:PassRole"])),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-006") is not None

    def test_global_wildcard_triggers(self):
        role = _role("R", _policy("P", _allow(["*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-006") is not None


# ===========================================================================
# Section 9 — PRIV-ESC-007 (iam:AddUserToGroup)
# ===========================================================================

class TestPrivEsc007:

    def test_add_user_to_group_triggers(self):
        role = _role("R", _policy("P", _allow(["iam:AddUserToGroup"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-007") is not None

    def test_other_group_action_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:RemoveUserFromGroup"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-007") is None

    def test_list_groups_does_not_trigger(self):
        role = _role("R", _policy("P", _allow(["iam:ListGroups"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-007") is None

    def test_severity_is_high(self):
        role = _role("R", _policy("P", _allow(["iam:AddUserToGroup"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-007")
        assert finding.severity == "HIGH"

    def test_dangerous_actions_populated(self):
        role = _role("R", _policy("P", _allow(["iam:AddUserToGroup"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-007")
        assert "iam:AddUserToGroup" in finding.dangerous_actions

    def test_iam_star_triggers_007(self):
        role = _role("R", _policy("P", _allow(["iam:*"])))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-007") is not None


# ===========================================================================
# Section 10 — Deny / Allow interaction
# ===========================================================================

class TestDenyAllowInteraction:
    """Per spec: _has_action only checks Allow; Deny does not override Allow
    at the detector level.  These tests confirm Deny statements are simply
    not counted as granting actions."""

    def test_deny_alone_does_not_grant_action(self):
        role = _role("R", _policy("P", _deny(["iam:CreatePolicyVersion"])))
        result = _detect(role)
        assert result.findings == []

    def test_allow_with_deny_both_present_still_flags(self):
        # Design note: the detector reports *potential* paths.
        # A Deny in a different policy context could block at runtime, but
        # the detector intentionally does not attempt to model that.
        role = _role(
            "R",
            _policy("P",
                _deny(["iam:CreatePolicyVersion"]),
                _allow(["iam:CreatePolicyVersion"]),
            ),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_deny_does_not_activate_check(self):
        stmts = [_deny(["iam:AddUserToGroup"])]
        assert _has_action(stmts, "iam:AddUserToGroup") is False


# ===========================================================================
# Section 11 — Multiple policies on same role
# ===========================================================================

class TestMultiplePolicies:

    def test_dangerous_action_in_second_policy_detected(self):
        role = _role(
            "R",
            _policy("Safe", _allow(["s3:GetObject"])),
            _policy("Dangerous", _allow(["iam:CreatePolicyVersion"])),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_combined_actions_across_three_policies(self):
        role = _role(
            "R",
            _policy("P1", _allow(["iam:AttachRolePolicy"])),
            _policy("P2", _allow(["s3:PutObject"])),
            _policy("P3", _allow(["sts:AssumeRole"])),
        )
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-002") is not None

    def test_all_safe_policies_no_findings(self):
        role = _role(
            "R",
            _policy("P1", _allow(["s3:GetObject"])),
            _policy("P2", _allow(["ec2:DescribeInstances"])),
            _policy("P3", _allow(["cloudwatch:GetMetricData"])),
        )
        result = _detect(role)
        assert result.findings == []


# ===========================================================================
# Section 12 — Multiple findings on same role
# ===========================================================================

class TestMultipleFindings:

    def test_multiple_checks_fire_on_same_role(self):
        # Grant enough permissions to trigger 001, 004, and 007 simultaneously.
        role = _role(
            "R",
            _policy("P", _allow(["iam:CreatePolicyVersion", "iam:CreateLoginProfile", "iam:AddUserToGroup"])),
        )
        result = _detect(role)
        ids = {f.check_id for f in result.findings}
        assert "PRIV-ESC-001" in ids
        assert "PRIV-ESC-004" in ids
        assert "PRIV-ESC-007" in ids

    def test_admin_wildcard_triggers_all_seven_checks(self):
        role = _role(
            "R",
            _policy("AdminPolicy", _allow(["*"], resources=["*"])),
        )
        result = _detect(role)
        ids = {f.check_id for f in result.findings}
        # All 7 checks should fire.
        for i in range(1, 8):
            assert f"PRIV-ESC-00{i}" in ids, f"PRIV-ESC-00{i} missing"

    def test_finding_count_correct(self):
        role = _role(
            "R",
            _policy("P", _allow(["iam:CreatePolicyVersion", "iam:CreateLoginProfile"])),
        )
        result = _detect(role)
        ids = [f.check_id for f in result.findings]
        assert ids.count("PRIV-ESC-001") == 1
        assert ids.count("PRIV-ESC-004") == 1


# ===========================================================================
# Section 13 — risk_score calculation and capping
# ===========================================================================

class TestRiskScore:

    def test_single_critical_weight(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        result = _detect(role)
        assert result.risk_score == 45

    def test_single_high_weight_004(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile"])))
        result = _detect(role)
        assert result.risk_score == 30

    def test_single_high_weight_007(self):
        role = _role("R", _policy("P", _allow(["iam:AddUserToGroup"])))
        result = _detect(role)
        assert result.risk_score == 25

    def test_two_checks_sum(self):
        # PRIV-ESC-004 (30) + PRIV-ESC-007 (25) = 55
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile", "iam:AddUserToGroup"])))
        result = _detect(role)
        assert result.risk_score == 55

    def test_score_capped_at_100(self):
        # Three CRITICAL checks: 001 (45) + 002 (45) + 003 (45) = 135 → capped at 100.
        role = _role(
            "R",
            _policy("P",
                _allow(["iam:CreatePolicyVersion"]),
                _allow(["iam:AttachRolePolicy", "sts:AssumeRole"]),
                _allow(["iam:PassRole"], resources=["*"]),
            ),
        )
        result = _detect(role)
        assert result.risk_score == 100

    def test_admin_wildcard_score_capped_at_100(self):
        role = _role("R", _policy("P", _allow(["*"], resources=["*"])))
        result = _detect(role)
        assert result.risk_score == 100

    def test_zero_score_for_clean_role(self):
        role = _role("R", _policy("P", _allow(["s3:GetObject"])))
        result = _detect(role)
        assert result.risk_score == 0

    def test_check_weights_dict_has_all_seven(self):
        assert len(_CHECK_WEIGHTS) == 7
        for i in range(1, 8):
            assert f"PRIV-ESC-00{i}" in _CHECK_WEIGHTS


# ===========================================================================
# Section 14 — by_severity() and summary()
# ===========================================================================

class TestBySeverity:

    def test_empty_result_returns_empty_dict(self):
        role = _role("R", _policy("P", _allow(["s3:GetObject"])))
        result = _detect(role)
        assert result.by_severity() == {}

    def test_critical_finding_appears_in_critical_key(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        sev_map = _detect(role).by_severity()
        assert "CRITICAL" in sev_map
        assert len(sev_map["CRITICAL"]) == 1

    def test_high_finding_appears_in_high_key(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile"])))
        sev_map = _detect(role).by_severity()
        assert "HIGH" in sev_map
        assert len(sev_map["HIGH"]) == 1

    def test_mixed_severities_grouped_correctly(self):
        role = _role(
            "R",
            _policy("P",
                _allow(["iam:CreatePolicyVersion"]),        # CRITICAL (001)
                _allow(["iam:CreateLoginProfile"]),          # HIGH (004)
                _allow(["iam:AddUserToGroup"]),              # HIGH (007)
            ),
        )
        sev_map = _detect(role).by_severity()
        assert len(sev_map["CRITICAL"]) == 1
        assert len(sev_map["HIGH"]) == 2

    def test_by_severity_values_are_lists_of_findings(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        sev_map = _detect(role).by_severity()
        for val in sev_map.values():
            assert isinstance(val, list)
            for item in val:
                assert isinstance(item, PrivEscFinding)


class TestSummary:

    def test_clean_role_summary_contains_no_findings(self):
        role = _role("SafeRole", _policy("P", _allow(["s3:GetObject"])))
        summary = _detect(role).summary()
        assert "SafeRole" in summary
        assert "risk_score=0" in summary

    def test_summary_contains_role_name(self):
        role = _role("DangerRole", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        summary = _detect(role).summary()
        assert "DangerRole" in summary

    def test_summary_contains_risk_score(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        summary = _detect(role).summary()
        assert "risk_score=" in summary

    def test_summary_mentions_critical(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        summary = _detect(role).summary()
        assert "CRITICAL" in summary

    def test_summary_contains_finding_count(self):
        role = _role("R", _policy("P", _allow(["iam:CreateLoginProfile", "iam:AddUserToGroup"])))
        summary = _detect(role).summary()
        assert "2" in summary

    def test_summary_is_string(self):
        role = _role("R")
        assert isinstance(_detect(role).summary(), str)


# ===========================================================================
# Section 15 — analyze_many()
# ===========================================================================

class TestAnalyzeMany:

    def test_returns_list(self):
        detector = PrivilegeEscalationDetector()
        results = detector.analyze_many([_role("A"), _role("B")])
        assert isinstance(results, list)

    def test_returns_correct_count(self):
        roles = [_role(f"R{i}") for i in range(5)]
        detector = PrivilegeEscalationDetector()
        results = detector.analyze_many(roles)
        assert len(results) == 5

    def test_empty_list_returns_empty_list(self):
        detector = PrivilegeEscalationDetector()
        assert detector.analyze_many([]) == []

    def test_each_result_matches_corresponding_role(self):
        roles = [
            _role("SafeRole", _policy("P", _allow(["s3:GetObject"]))),
            _role("DangerRole", _policy("P", _allow(["iam:CreatePolicyVersion"]))),
        ]
        detector = PrivilegeEscalationDetector()
        results = detector.analyze_many(roles)
        assert results[0].role_name == "SafeRole"
        assert results[1].role_name == "DangerRole"
        assert len(results[0].findings) == 0
        assert len(results[1].findings) > 0

    def test_analyze_many_applies_all_checks(self):
        roles = [_role("R", _policy("P", _allow(["*"], resources=["*"])))]
        detector = PrivilegeEscalationDetector()
        results = detector.analyze_many(roles)
        ids = {f.check_id for f in results[0].findings}
        assert len(ids) == 7


# ===========================================================================
# Section 16 — to_dict() on all dataclasses
# ===========================================================================

class TestToDict:

    def test_iam_statement_to_dict_keys(self):
        stmt = _allow(["iam:CreatePolicyVersion"], resources=["*"], conditions={"key": "val"})
        d = stmt.to_dict()
        assert set(d.keys()) == {"effect", "actions", "resources", "conditions"}
        assert d["effect"] == "Allow"
        assert "iam:CreatePolicyVersion" in d["actions"]
        assert "*" in d["resources"]
        assert d["conditions"] == {"key": "val"}

    def test_iam_statement_to_dict_deny(self):
        stmt = _deny(["iam:*"])
        d = stmt.to_dict()
        assert d["effect"] == "Deny"

    def test_iam_policy_doc_to_dict_keys(self):
        policy = _policy("MyPolicy", _allow(["s3:GetObject"]))
        d = policy.to_dict()
        assert set(d.keys()) == {"policy_name", "statements"}
        assert d["policy_name"] == "MyPolicy"
        assert isinstance(d["statements"], list)
        assert len(d["statements"]) == 1

    def test_iam_policy_doc_to_dict_nested_statement(self):
        policy = _policy("P", _allow(["iam:ListRoles"]))
        d = policy.to_dict()
        assert d["statements"][0]["effect"] == "Allow"

    def test_iam_role_to_dict_keys(self):
        role = _role("MyRole", _policy("P", _allow(["s3:GetObject"])))
        d = role.to_dict()
        assert set(d.keys()) == {"role_name", "role_arn", "policies"}
        assert d["role_name"] == "MyRole"
        assert "arn:aws:iam" in d["role_arn"]
        assert isinstance(d["policies"], list)

    def test_iam_role_to_dict_nested(self):
        role = _role("R", _policy("P", _allow(["s3:GetObject"])))
        d = role.to_dict()
        assert d["policies"][0]["policy_name"] == "P"

    def test_priv_esc_finding_to_dict_keys(self):
        finding = PrivEscFinding(
            check_id="PRIV-ESC-001",
            severity="CRITICAL",
            role_name="R",
            role_arn="arn:aws:iam::123:role/R",
            dangerous_actions=["iam:CreatePolicyVersion"],
            message="Test message",
            remediation="Test remediation",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "role_name", "role_arn",
            "dangerous_actions", "message", "remediation",
        }
        assert d["check_id"] == "PRIV-ESC-001"
        assert d["severity"] == "CRITICAL"
        assert "iam:CreatePolicyVersion" in d["dangerous_actions"]

    def test_priv_esc_result_to_dict_keys(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        d = _detect(role).to_dict()
        assert set(d.keys()) == {"role_name", "role_arn", "findings", "risk_score", "summary"}

    def test_priv_esc_result_to_dict_findings_are_dicts(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        d = _detect(role).to_dict()
        for item in d["findings"]:
            assert isinstance(item, dict)
            assert "check_id" in item

    def test_priv_esc_result_to_dict_risk_score(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        d = _detect(role).to_dict()
        assert d["risk_score"] == 45

    def test_priv_esc_result_to_dict_summary_is_string(self):
        role = _role("R")
        d = _detect(role).to_dict()
        assert isinstance(d["summary"], str)

    def test_empty_conditions_in_statement(self):
        stmt = IAMStatement(effect="Allow", actions=["s3:*"], resources=["*"], conditions={})
        d = stmt.to_dict()
        assert d["conditions"] == {}


# ===========================================================================
# Section 17 — Finding metadata correctness
# ===========================================================================

class TestFindingMetadata:

    def test_finding_role_name_matches(self):
        role = _role("SpecificRole", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert finding.role_name == "SpecificRole"

    def test_finding_role_arn_matches(self):
        role = _role("SpecificRole", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert finding.role_arn == role.role_arn

    def test_finding_message_is_non_empty(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert len(finding.message) > 0

    def test_finding_remediation_is_non_empty(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert len(finding.remediation) > 0

    def test_finding_dangerous_actions_is_list(self):
        role = _role("R", _policy("P", _allow(["iam:CreatePolicyVersion"])))
        finding = _find_by_id(_detect(role), "PRIV-ESC-001")
        assert isinstance(finding.dangerous_actions, list)

    def test_all_checks_have_weights(self):
        for check_id in [f"PRIV-ESC-00{i}" for i in range(1, 8)]:
            assert check_id in _CHECK_WEIGHTS
            assert _CHECK_WEIGHTS[check_id] > 0


# ===========================================================================
# Section 18 — Edge cases
# ===========================================================================

class TestEdgeCases:

    def test_role_with_no_policies(self):
        role = _role("Empty")
        result = _detect(role)
        assert result.findings == []
        assert result.risk_score == 0

    def test_role_with_policy_with_no_statements(self):
        role = _role("R", _policy("EmptyPolicy"))
        result = _detect(role)
        assert result.findings == []

    def test_conditions_on_allow_stmt_still_detected(self):
        # Conditions do not prevent the detector from flagging; conditions are
        # not evaluated at static-analysis time.
        stmt = IAMStatement(
            effect="Allow",
            actions=["iam:CreatePolicyVersion"],
            resources=["*"],
            conditions={"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}},
        )
        role = _role("R", _policy("P", stmt))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_case_insensitive_effect_allow(self):
        stmt = IAMStatement(effect="allow", actions=["iam:CreatePolicyVersion"], resources=["*"])
        role = _role("R", _policy("P", stmt))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is not None

    def test_case_insensitive_effect_deny(self):
        stmt = IAMStatement(effect="DENY", actions=["iam:CreatePolicyVersion"], resources=["*"])
        role = _role("R", _policy("P", stmt))
        result = _detect(role)
        assert _find_by_id(result, "PRIV-ESC-001") is None

    def test_passrole_with_multiple_resources_including_star(self):
        # resource list contains both a specific ARN and "*" — should trigger 003
        stmts = [
            _allow(["iam:PassRole"], resources=["arn:aws:iam::123:role/Foo", "*"])
        ]
        assert _has_passrole_with_wildcard_resource(stmts) is True

    def test_analyze_many_single_role(self):
        results = PrivilegeEscalationDetector().analyze_many([_role("R")])
        assert len(results) == 1

    def test_result_role_name_and_arn_on_clean_result(self):
        role = _role("CleanRole")
        result = _detect(role)
        assert result.role_name == "CleanRole"
        assert "CleanRole" in result.role_arn

    def test_sts_wildcard_covers_assume_role(self):
        stmts = [_allow(["sts:*"])]
        assert _has_action(stmts, "sts:AssumeRole") is True

    def test_ec2_wildcard_does_not_cover_iam_action(self):
        stmts = [_allow(["ec2:*"])]
        assert _has_action(stmts, "iam:CreatePolicyVersion") is False
