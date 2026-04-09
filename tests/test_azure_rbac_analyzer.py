# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi — Cyber Port
"""
Test suite for analyzers.azure_rbac_analyzer
=============================================
90+ pytest tests covering all 7 check rules, edge cases, data-model contracts,
and aggregation behaviour (risk_score, by_severity, summary, to_dict).

Run with:
    python3 -m pytest tests/test_azure_rbac_analyzer.py --override-ini="addopts=" -q
"""
from __future__ import annotations

import sys
import os

# ---------------------------------------------------------------------------
# Path fixup — allow running from the repo root without installing the package
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analyzers.azure_rbac_analyzer import (
    AzureCustomRole,
    AzureRBACAnalyzer,
    AzureRBACFinding,
    AzureRBACResult,
    AzureRoleAssignment,
    AzureRBACseverity,
    _CHECK_WEIGHTS,
    _is_management_group_scope,
    _is_subscription_scope,
)


# ===========================================================================
# Fixtures / helpers
# ===========================================================================

def make_assignment(
    *,
    assignment_id: str = "ra-test",
    principal_name: str = "test@contoso.com",
    principal_type: str = "User",
    role_name: str = "Reader",
    scope: str = "/subscriptions/sub-abc/resourceGroups/rg1",
    is_classic_admin: bool = False,
    is_pim_eligible: bool = False,
    principal_is_guest: bool = False,
) -> AzureRoleAssignment:
    """Return a minimally-configured AzureRoleAssignment for testing."""
    return AzureRoleAssignment(
        assignment_id=assignment_id,
        principal_name=principal_name,
        principal_type=principal_type,
        role_name=role_name,
        scope=scope,
        is_classic_admin=is_classic_admin,
        is_pim_eligible=is_pim_eligible,
        principal_is_guest=principal_is_guest,
    )


def make_custom_role(
    *,
    role_id: str = "cr-test",
    role_name: str = "TestCustomRole",
    actions: list | None = None,
    not_actions: list | None = None,
    scope: str = "/subscriptions/sub-abc",
) -> AzureCustomRole:
    """Return a minimally-configured AzureCustomRole for testing."""
    return AzureCustomRole(
        role_id=role_id,
        role_name=role_name,
        actions=actions if actions is not None else ["Microsoft.Compute/*/read"],
        not_actions=not_actions if not_actions is not None else [],
        scope=scope,
    )


@pytest.fixture()
def analyzer() -> AzureRBACAnalyzer:
    return AzureRBACAnalyzer()


# ===========================================================================
# Helper function tests
# ===========================================================================

class TestIsSubscriptionScope:
    def test_subscription_only(self):
        assert _is_subscription_scope("/subscriptions/abc123") is True

    def test_subscription_with_trailing_slash(self):
        # Trailing slash still resolves to 2 non-empty parts
        assert _is_subscription_scope("/subscriptions/abc123/") is True

    def test_resource_group_scope_is_not_subscription(self):
        assert _is_subscription_scope(
            "/subscriptions/abc123/resourceGroups/rg1"
        ) is False

    def test_resource_level_scope_is_not_subscription(self):
        assert _is_subscription_scope(
            "/subscriptions/abc123/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        ) is False

    def test_management_group_scope_is_not_subscription(self):
        assert _is_subscription_scope(
            "/providers/Microsoft.Management/managementGroups/mg1"
        ) is False

    def test_empty_string_is_not_subscription(self):
        assert _is_subscription_scope("") is False

    def test_root_slash_is_not_subscription(self):
        assert _is_subscription_scope("/") is False


class TestIsManagementGroupScope:
    def test_management_group_scope(self):
        assert _is_management_group_scope(
            "/providers/Microsoft.Management/managementGroups/mg1"
        ) is True

    def test_subscription_is_not_mg(self):
        assert _is_management_group_scope("/subscriptions/abc123") is False

    def test_resource_group_is_not_mg(self):
        assert _is_management_group_scope(
            "/subscriptions/abc123/resourceGroups/rg1"
        ) is False

    def test_empty_string_is_not_mg(self):
        assert _is_management_group_scope("") is False


# ===========================================================================
# AzureRoleAssignment.to_dict
# ===========================================================================

class TestAzureRoleAssignmentToDict:
    def test_to_dict_contains_all_keys(self):
        a = make_assignment()
        d = a.to_dict()
        expected_keys = {
            "assignment_id", "principal_name", "principal_type",
            "role_name", "scope", "is_classic_admin",
            "is_pim_eligible", "principal_is_guest",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values_match(self):
        a = make_assignment(
            assignment_id="x1",
            principal_name="alice@corp.com",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_classic_admin=True,
            is_pim_eligible=True,
            principal_is_guest=True,
        )
        d = a.to_dict()
        assert d["assignment_id"] == "x1"
        assert d["principal_name"] == "alice@corp.com"
        assert d["role_name"] == "Owner"
        assert d["is_classic_admin"] is True
        assert d["is_pim_eligible"] is True
        assert d["principal_is_guest"] is True

    def test_to_dict_defaults(self):
        a = make_assignment()
        d = a.to_dict()
        assert d["is_classic_admin"] is False
        assert d["is_pim_eligible"] is False
        assert d["principal_is_guest"] is False


# ===========================================================================
# AzureCustomRole.to_dict
# ===========================================================================

class TestAzureCustomRoleToDict:
    def test_to_dict_contains_all_keys(self):
        r = make_custom_role()
        d = r.to_dict()
        assert set(d.keys()) == {"role_id", "role_name", "actions", "not_actions", "scope"}

    def test_to_dict_values_match(self):
        r = make_custom_role(
            role_id="cr-1",
            role_name="MyRole",
            actions=["*"],
            not_actions=["Microsoft.Authorization/*/write"],
            scope="/subscriptions/sub-1",
        )
        d = r.to_dict()
        assert d["role_id"] == "cr-1"
        assert d["actions"] == ["*"]
        assert d["not_actions"] == ["Microsoft.Authorization/*/write"]

    def test_to_dict_actions_is_new_list(self):
        # Mutation of returned list must not affect original
        r = make_custom_role(actions=["Microsoft.Compute/*/read"])
        d = r.to_dict()
        d["actions"].append("extra")
        assert r.actions == ["Microsoft.Compute/*/read"]


# ===========================================================================
# AzureRBACFinding.to_dict
# ===========================================================================

class TestAzureRBACFindingToDict:
    def test_to_dict_keys(self):
        f = AzureRBACFinding(
            check_id="AZ-RBAC-001",
            severity=AzureRBACseverity.CRITICAL,
            principal_name="alice",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            message="msg",
            recommendation="rec",
        )
        d = f.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "principal_name", "principal_type",
            "role_name", "scope", "message", "recommendation",
        }

    def test_to_dict_severity_is_string(self):
        f = AzureRBACFinding(
            check_id="AZ-RBAC-001",
            severity=AzureRBACseverity.CRITICAL,
            principal_name="alice",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            message="msg",
            recommendation="rec",
        )
        assert f.to_dict()["severity"] == "CRITICAL"


# ===========================================================================
# AzureRBACResult
# ===========================================================================

class TestAzureRBACResult:
    def _make_finding(self, check_id: str, severity: AzureRBACseverity) -> AzureRBACFinding:
        return AzureRBACFinding(
            check_id=check_id,
            severity=severity,
            principal_name="alice",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            message="msg",
            recommendation="rec",
        )

    def test_empty_result_defaults(self):
        r = AzureRBACResult()
        assert r.findings == []
        assert r.risk_score == 0

    def test_by_severity_empty(self):
        r = AzureRBACResult()
        assert r.by_severity() == {}

    def test_by_severity_groups_correctly(self):
        f1 = self._make_finding("AZ-RBAC-001", AzureRBACseverity.CRITICAL)
        f2 = self._make_finding("AZ-RBAC-003", AzureRBACseverity.CRITICAL)
        f3 = self._make_finding("AZ-RBAC-002", AzureRBACseverity.HIGH)
        f4 = self._make_finding("AZ-RBAC-006", AzureRBACseverity.MEDIUM)
        r = AzureRBACResult(findings=[f1, f2, f3, f4], risk_score=50)
        bysev = r.by_severity()
        assert len(bysev["CRITICAL"]) == 2
        assert len(bysev["HIGH"]) == 1
        assert len(bysev["MEDIUM"]) == 1
        assert "LOW" not in bysev

    def test_summary_format(self):
        f1 = self._make_finding("AZ-RBAC-001", AzureRBACseverity.CRITICAL)
        r = AzureRBACResult(findings=[f1], risk_score=40)
        s = r.summary()
        assert "risk_score=40" in s
        assert "CRITICAL=1" in s
        assert "HIGH=0" in s
        assert "1 finding" in s

    def test_summary_zero_findings(self):
        r = AzureRBACResult()
        s = r.summary()
        assert "0 finding" in s
        assert "risk_score=0" in s

    def test_to_dict_keys(self):
        r = AzureRBACResult()
        d = r.to_dict()
        expected = {"risk_score", "generated_at", "total", "critical",
                    "high", "medium", "low", "findings"}
        assert set(d.keys()) == expected

    def test_to_dict_findings_are_dicts(self):
        f = self._make_finding("AZ-RBAC-001", AzureRBACseverity.CRITICAL)
        r = AzureRBACResult(findings=[f], risk_score=40)
        d = r.to_dict()
        assert isinstance(d["findings"][0], dict)
        assert d["findings"][0]["check_id"] == "AZ-RBAC-001"

    def test_to_dict_counts(self):
        f1 = self._make_finding("AZ-RBAC-001", AzureRBACseverity.CRITICAL)
        f2 = self._make_finding("AZ-RBAC-006", AzureRBACseverity.MEDIUM)
        r = AzureRBACResult(findings=[f1, f2], risk_score=55)
        d = r.to_dict()
        assert d["total"] == 2
        assert d["critical"] == 1
        assert d["medium"] == 1
        assert d["high"] == 0


# ===========================================================================
# Clean inputs — no findings expected
# ===========================================================================

class TestCleanInputs:
    def test_empty_assignments_returns_no_findings(self, analyzer):
        result = analyzer.analyze([])
        assert result.findings == []
        assert result.risk_score == 0

    def test_reader_at_rg_scope_no_findings(self, analyzer):
        a = make_assignment(
            role_name="Reader",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
        )
        result = analyzer.analyze([a])
        assert result.findings == []
        assert result.risk_score == 0

    def test_contributor_at_rg_scope_with_pim_no_001(self, analyzer):
        # PIM-eligible at RG scope should not trigger 001 (sub scope) or 005
        # (PIM is set), but WILL trigger 005 is False because is_pim_eligible=True
        a = make_assignment(
            role_name="Contributor",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        # PIM eligible, so 001 and 005 should NOT fire
        check_ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" not in check_ids
        assert "AZ-RBAC-005" not in check_ids

    def test_non_privileged_role_no_findings(self, analyzer):
        for role in ("Reader", "Monitoring Reader", "Storage Blob Data Reader"):
            a = make_assignment(role_name=role, scope="/subscriptions/sub-1")
            result = analyzer.analyze([a])
            assert result.findings == [], f"Unexpected findings for role={role}"

    def test_custom_role_without_wildcard_no_findings(self, analyzer):
        r = make_custom_role(actions=["Microsoft.Compute/*/read", "Microsoft.Network/virtualNetworks/read"])
        result = analyzer.analyze([], custom_roles=[r])
        assert result.findings == []
        assert result.risk_score == 0


# ===========================================================================
# AZ-RBAC-001
# ===========================================================================

class TestAzRbac001:
    def test_owner_at_subscription_scope_without_pim_triggers(self, analyzer):
        a = make_assignment(
            role_name="Owner",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" in ids

    def test_contributor_at_subscription_scope_without_pim_triggers(self, analyzer):
        a = make_assignment(
            role_name="Contributor",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" in ids

    def test_user_access_admin_at_subscription_scope_without_pim_triggers(self, analyzer):
        a = make_assignment(
            role_name="User Access Administrator",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" in ids

    def test_owner_at_rg_scope_does_not_trigger_001(self, analyzer):
        a = make_assignment(
            role_name="Owner",
            scope="/subscriptions/sub-abc/resourceGroups/rg1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" not in ids

    def test_owner_at_subscription_scope_with_pim_does_not_trigger_001(self, analyzer):
        a = make_assignment(
            role_name="Owner",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" not in ids

    def test_001_finding_severity_is_critical(self, analyzer):
        a = make_assignment(
            role_name="Owner",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        f001 = [f for f in result.findings if f.check_id == "AZ-RBAC-001"]
        assert len(f001) >= 1
        assert f001[0].severity == AzureRBACseverity.CRITICAL

    def test_001_finding_contains_principal_name(self, analyzer):
        a = make_assignment(
            principal_name="privileged@contoso.com",
            role_name="Owner",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        f001 = [f for f in result.findings if f.check_id == "AZ-RBAC-001"][0]
        assert "privileged@contoso.com" in f001.message

    def test_reader_at_subscription_scope_does_not_trigger_001(self, analyzer):
        a = make_assignment(
            role_name="Reader",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" not in ids

    def test_001_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-001"] == 40


# ===========================================================================
# AZ-RBAC-002
# ===========================================================================

class TestAzRbac002:
    def test_classic_admin_triggers_002(self, analyzer):
        a = make_assignment(is_classic_admin=True)
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-002" in ids

    def test_non_classic_admin_does_not_trigger_002(self, analyzer):
        a = make_assignment(is_classic_admin=False)
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-002" not in ids

    def test_002_finding_severity_is_high(self, analyzer):
        a = make_assignment(is_classic_admin=True)
        result = analyzer.analyze([a])
        f002 = [f for f in result.findings if f.check_id == "AZ-RBAC-002"]
        assert f002[0].severity == AzureRBACseverity.HIGH

    def test_002_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-002"] == 25

    def test_002_finding_principal_name_present(self, analyzer):
        a = make_assignment(
            principal_name="legacy-admin@corp.com",
            is_classic_admin=True,
        )
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-002"][0]
        assert "legacy-admin@corp.com" in f.message


# ===========================================================================
# AZ-RBAC-003
# ===========================================================================

class TestAzRbac003:
    def test_sp_with_owner_triggers_003(self, analyzer):
        a = make_assignment(
            principal_type="ServicePrincipal",
            role_name="Owner",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-003" in ids

    def test_sp_with_contributor_does_not_trigger_003(self, analyzer):
        a = make_assignment(
            principal_type="ServicePrincipal",
            role_name="Contributor",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-003" not in ids

    def test_user_with_owner_does_not_trigger_003(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",  # RG scope avoids 001
            is_pim_eligible=True,                              # PIM avoids 005
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-003" not in ids

    def test_003_finding_severity_is_critical(self, analyzer):
        a = make_assignment(
            principal_type="ServicePrincipal",
            role_name="Owner",
        )
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-003"][0]
        assert f.severity == AzureRBACseverity.CRITICAL

    def test_003_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-003"] == 35

    def test_003_finding_message_contains_sp_name(self, analyzer):
        a = make_assignment(
            principal_name="my-automation-sp",
            principal_type="ServicePrincipal",
            role_name="Owner",
        )
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-003"][0]
        assert "my-automation-sp" in f.message


# ===========================================================================
# AZ-RBAC-004
# ===========================================================================

class TestAzRbac004:
    @pytest.mark.parametrize("role", [
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Security Admin",
        "Global Administrator",
    ])
    def test_guest_with_privileged_role_triggers_004(self, analyzer, role):
        a = make_assignment(
            principal_is_guest=True,
            role_name=role,
            is_pim_eligible=True,    # PIM avoids 001/005 interference
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-004" in ids, f"Expected 004 for guest with role={role}"

    def test_guest_with_reader_does_not_trigger_004(self, analyzer):
        a = make_assignment(
            principal_is_guest=True,
            role_name="Reader",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-004" not in ids

    def test_non_guest_with_privileged_role_does_not_trigger_004(self, analyzer):
        a = make_assignment(
            principal_is_guest=False,
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-004" not in ids

    def test_004_finding_severity_is_high(self, analyzer):
        a = make_assignment(
            principal_is_guest=True,
            role_name="Owner",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-004"][0]
        assert f.severity == AzureRBACseverity.HIGH

    def test_004_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-004"] == 25


# ===========================================================================
# AZ-RBAC-005
# ===========================================================================

class TestAzRbac005:
    def test_user_direct_owner_no_pim_triggers_005(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",  # RG scope — not sub
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-005" in ids

    def test_user_owner_with_pim_does_not_trigger_005(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-005" not in ids

    def test_sp_direct_owner_no_pim_does_not_trigger_005(self, analyzer):
        # 005 is User-only; SP with Owner triggers 003 instead
        a = make_assignment(
            principal_type="ServicePrincipal",
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-005" not in ids

    def test_group_direct_owner_no_pim_does_not_trigger_005(self, analyzer):
        # 005 is User-only
        a = make_assignment(
            principal_type="Group",
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-005" not in ids

    def test_005_finding_severity_is_high(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Contributor",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-005"][0]
        assert f.severity == AzureRBACseverity.HIGH

    def test_005_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-005"] == 20

    def test_user_contributor_no_pim_at_sub_scope_triggers_both_001_and_005(self, analyzer):
        # Sub scope + non-PIM + User should fire both 001 and 005
        a = make_assignment(
            principal_type="User",
            role_name="Contributor",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" in ids
        assert "AZ-RBAC-005" in ids


# ===========================================================================
# AZ-RBAC-006
# ===========================================================================

class TestAzRbac006:
    def test_custom_role_wildcard_triggers_006(self, analyzer):
        r = make_custom_role(actions=["*"])
        result = analyzer.analyze([], custom_roles=[r])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-006" in ids

    def test_custom_role_wildcard_in_list_triggers_006(self, analyzer):
        r = make_custom_role(actions=["Microsoft.Compute/*/read", "*"])
        result = analyzer.analyze([], custom_roles=[r])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-006" in ids

    def test_custom_role_no_wildcard_does_not_trigger_006(self, analyzer):
        r = make_custom_role(actions=["Microsoft.Compute/*/read"])
        result = analyzer.analyze([], custom_roles=[r])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-006" not in ids

    def test_custom_role_partial_wildcard_not_bare_wildcard_does_not_trigger(self, analyzer):
        # "Microsoft.Compute/*" is NOT a bare "*"
        r = make_custom_role(actions=["Microsoft.Compute/*"])
        result = analyzer.analyze([], custom_roles=[r])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-006" not in ids

    def test_006_finding_severity_is_medium(self, analyzer):
        r = make_custom_role(actions=["*"])
        result = analyzer.analyze([], custom_roles=[r])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-006"][0]
        assert f.severity == AzureRBACseverity.MEDIUM

    def test_006_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-006"] == 15

    def test_006_finding_contains_role_name(self, analyzer):
        r = make_custom_role(role_name="SuperWidgetRole", actions=["*"])
        result = analyzer.analyze([], custom_roles=[r])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-006"][0]
        assert "SuperWidgetRole" in f.message

    def test_multiple_wildcard_custom_roles_produce_multiple_findings(self, analyzer):
        r1 = make_custom_role(role_id="cr-1", role_name="Role1", actions=["*"])
        r2 = make_custom_role(role_id="cr-2", role_name="Role2", actions=["*"])
        result = analyzer.analyze([], custom_roles=[r1, r2])
        f006 = [f for f in result.findings if f.check_id == "AZ-RBAC-006"]
        assert len(f006) == 2

    def test_no_custom_roles_passed_no_006_findings(self, analyzer):
        result = analyzer.analyze([])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-006" not in ids

    def test_none_custom_roles_no_006_findings(self, analyzer):
        result = analyzer.analyze([], custom_roles=None)
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-006" not in ids


# ===========================================================================
# AZ-RBAC-007
# ===========================================================================

class TestAzRbac007:
    def test_assignment_at_mg_scope_triggers_007(self, analyzer):
        a = make_assignment(
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-007" in ids

    def test_assignment_at_subscription_scope_does_not_trigger_007(self, analyzer):
        a = make_assignment(
            role_name="Reader",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-007" not in ids

    def test_assignment_at_rg_scope_does_not_trigger_007(self, analyzer):
        a = make_assignment(
            scope="/subscriptions/sub-abc/resourceGroups/rg1",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-007" not in ids

    def test_007_finding_severity_is_critical(self, analyzer):
        a = make_assignment(
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-007"][0]
        assert f.severity == AzureRBACseverity.CRITICAL

    def test_007_weight_correct(self):
        assert _CHECK_WEIGHTS["AZ-RBAC-007"] == 40

    def test_007_finding_contains_scope(self, analyzer):
        scope = "/providers/Microsoft.Management/managementGroups/rootMG"
        a = make_assignment(scope=scope)
        result = analyzer.analyze([a])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-007"][0]
        assert scope in f.message

    def test_007_reader_at_mg_scope_still_triggers(self, analyzer):
        # Even Reader at MG scope is flagged due to blast radius
        a = make_assignment(
            role_name="Reader",
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-007" in ids


# ===========================================================================
# Risk score calculation
# ===========================================================================

class TestRiskScore:
    def test_no_findings_risk_score_zero(self, analyzer):
        result = analyzer.analyze([])
        assert result.risk_score == 0

    def test_single_check_risk_score_equals_weight(self, analyzer):
        # AZ-RBAC-002 only (classic admin) — weight 25
        a = make_assignment(is_classic_admin=True, role_name="Reader")
        result = analyzer.analyze([a])
        # Only 002 should fire for a Reader with classic admin flag
        # (Reader is non-privileged, so 001/003/004/005 won't fire)
        assert _CHECK_WEIGHTS["AZ-RBAC-002"] == 25
        ids = {f.check_id for f in result.findings}
        expected_score = sum(_CHECK_WEIGHTS[c] for c in ids)
        assert result.risk_score == min(100, expected_score)

    def test_risk_score_uses_unique_check_ids_only(self, analyzer):
        # Two assignments both triggering AZ-RBAC-001 should count weight once
        a1 = make_assignment(
            assignment_id="ra-1",
            principal_name="alice@corp.com",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_pim_eligible=False,
        )
        a2 = make_assignment(
            assignment_id="ra-2",
            principal_name="bob@corp.com",
            role_name="Owner",
            scope="/subscriptions/sub-2",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a1, a2])
        fired = {f.check_id for f in result.findings}
        expected = min(100, sum(_CHECK_WEIGHTS[c] for c in fired))
        assert result.risk_score == expected

    def test_risk_score_capped_at_100(self, analyzer):
        # Fire as many high-weight checks as possible simultaneously
        a1 = make_assignment(                             # 001 (40) + 005 (20)
            assignment_id="ra-1",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_pim_eligible=False,
        )
        a2 = make_assignment(                             # 002 (25)
            assignment_id="ra-2",
            is_classic_admin=True,
        )
        a3 = make_assignment(                             # 003 (35)
            assignment_id="ra-3",
            principal_type="ServicePrincipal",
            role_name="Owner",
        )
        a4 = make_assignment(                             # 007 (40)
            assignment_id="ra-4",
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        r = make_custom_role(actions=["*"])               # 006 (15)
        result = analyzer.analyze([a1, a2, a3, a4], custom_roles=[r])
        assert result.risk_score <= 100
        # Total weights: 001=40 + 002=25 + 003=35 + 005=20 + 006=15 + 007=40 = 175 → capped at 100
        assert result.risk_score == 100

    def test_risk_score_is_int(self, analyzer):
        result = analyzer.analyze([])
        assert isinstance(result.risk_score, int)

    def test_risk_score_cumulative_for_different_checks(self, analyzer):
        # 002 (25) + 007 (40) = 65
        a1 = make_assignment(
            assignment_id="ra-1",
            is_classic_admin=True,
            role_name="Reader",
        )
        a2 = make_assignment(
            assignment_id="ra-2",
            role_name="Reader",
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        result = analyzer.analyze([a1, a2])
        fired = {f.check_id for f in result.findings}
        expected = min(100, sum(_CHECK_WEIGHTS[c] for c in fired))
        assert result.risk_score == expected


# ===========================================================================
# Multiple checks firing simultaneously
# ===========================================================================

class TestMultipleChecksFiring:
    def test_001_and_005_fire_together_for_user_at_sub_scope(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" in ids
        assert "AZ-RBAC-005" in ids

    def test_003_and_007_fire_together_for_sp_at_mg_scope(self, analyzer):
        a = make_assignment(
            principal_type="ServicePrincipal",
            role_name="Owner",
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-003" in ids
        assert "AZ-RBAC-007" in ids

    def test_all_checks_can_fire_in_one_analyze_call(self, analyzer):
        a1 = make_assignment(                        # 001 + 005
            assignment_id="ra-1",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_pim_eligible=False,
        )
        a2 = make_assignment(                        # 002
            assignment_id="ra-2",
            is_classic_admin=True,
            role_name="Reader",
        )
        a3 = make_assignment(                        # 003
            assignment_id="ra-3",
            principal_type="ServicePrincipal",
            role_name="Owner",
            scope="/subscriptions/sub-1/resourceGroups/rg1",
        )
        a4 = make_assignment(                        # 004
            assignment_id="ra-4",
            principal_is_guest=True,
            role_name="Contributor",
            is_pim_eligible=True,
        )
        a5 = make_assignment(                        # 007
            assignment_id="ra-5",
            role_name="Reader",
            scope="/providers/Microsoft.Management/managementGroups/mg1",
        )
        r = make_custom_role(actions=["*"])          # 006
        result = analyzer.analyze([a1, a2, a3, a4, a5], custom_roles=[r])
        ids = {f.check_id for f in result.findings}
        for expected_id in [
            "AZ-RBAC-001", "AZ-RBAC-002", "AZ-RBAC-003",
            "AZ-RBAC-004", "AZ-RBAC-005", "AZ-RBAC-006", "AZ-RBAC-007",
        ]:
            assert expected_id in ids, f"Expected {expected_id} to fire"

    def test_classic_admin_guest_owner_at_sub_scope_multiple_checks(self, analyzer):
        # One assignment with multiple flags set
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_classic_admin=True,
            is_pim_eligible=False,
            principal_is_guest=True,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        # 001 (sub scope, no PIM), 002 (classic admin), 004 (guest + Owner), 005 (User, no PIM)
        assert "AZ-RBAC-001" in ids
        assert "AZ-RBAC-002" in ids
        assert "AZ-RBAC-004" in ids
        assert "AZ-RBAC-005" in ids


# ===========================================================================
# analyze_many
# ===========================================================================

class TestAnalyzeMany:
    def test_analyze_many_returns_list(self, analyzer):
        result = analyzer.analyze_many([[]])
        assert isinstance(result, list)

    def test_analyze_many_correct_length(self, analyzer):
        results = analyzer.analyze_many([[], [], []])
        assert len(results) == 3

    def test_analyze_many_each_element_is_azure_rbac_result(self, analyzer):
        results = analyzer.analyze_many([[]])
        assert all(isinstance(r, AzureRBACResult) for r in results)

    def test_analyze_many_independent_scopes(self, analyzer):
        # First set: clean; second set: has a finding
        a = make_assignment(is_classic_admin=True, role_name="Reader")
        results = analyzer.analyze_many([[], [a]])
        assert results[0].findings == []
        assert any(f.check_id == "AZ-RBAC-002" for f in results[1].findings)

    def test_analyze_many_with_custom_role_sets(self, analyzer):
        r = make_custom_role(actions=["*"])
        results = analyzer.analyze_many([[]], custom_role_sets=[[r]])
        ids = {f.check_id for f in results[0].findings}
        assert "AZ-RBAC-006" in ids

    def test_analyze_many_empty_list_returns_empty(self, analyzer):
        results = analyzer.analyze_many([])
        assert results == []

    def test_analyze_many_none_custom_role_set_does_not_error(self, analyzer):
        results = analyzer.analyze_many([[]], custom_role_sets=[None])
        assert len(results) == 1


# ===========================================================================
# Finding message and recommendation fields
# ===========================================================================

class TestFindingMessageAndRecommendation:
    def test_all_findings_have_non_empty_message(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        for f in result.findings:
            assert f.message.strip() != "", f"Empty message for {f.check_id}"

    def test_all_findings_have_non_empty_recommendation(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
            is_pim_eligible=False,
        )
        result = analyzer.analyze([a])
        for f in result.findings:
            assert f.recommendation.strip() != "", f"Empty rec for {f.check_id}"

    def test_006_finding_principal_name_is_empty_string(self, analyzer):
        # 006 is a role-level finding with no associated principal
        r = make_custom_role(actions=["*"])
        result = analyzer.analyze([], custom_roles=[r])
        f = [f for f in result.findings if f.check_id == "AZ-RBAC-006"][0]
        assert f.principal_name == ""
        assert f.principal_type == ""


# ===========================================================================
# PIM boundary conditions
# ===========================================================================

class TestPIMBoundaryConditions:
    def test_owner_at_sub_scope_with_pim_no_001_no_005(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-abc",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        ids = {f.check_id for f in result.findings}
        assert "AZ-RBAC-001" not in ids
        assert "AZ-RBAC-005" not in ids

    def test_contributor_at_rg_scope_with_pim_no_findings(self, analyzer):
        a = make_assignment(
            principal_type="User",
            role_name="Contributor",
            scope="/subscriptions/sub-abc/resourceGroups/rg1",
            is_pim_eligible=True,
        )
        result = analyzer.analyze([a])
        assert result.findings == []
        assert result.risk_score == 0


# ===========================================================================
# _CHECK_WEIGHTS completeness
# ===========================================================================

class TestCheckWeights:
    def test_all_seven_checks_have_weights(self):
        for i in range(1, 8):
            key = f"AZ-RBAC-{i:03d}"
            assert key in _CHECK_WEIGHTS, f"Missing weight for {key}"

    def test_all_weights_are_positive_integers(self):
        for key, weight in _CHECK_WEIGHTS.items():
            assert isinstance(weight, int), f"{key} weight is not int"
            assert weight > 0, f"{key} weight must be positive"

    def test_no_single_check_exceeds_100(self):
        for key, weight in _CHECK_WEIGHTS.items():
            assert weight <= 100, f"{key} weight {weight} exceeds 100"
