# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Hiago Kin Levi — Cyber Port
#
# This file is licensed under the Creative Commons Attribution 4.0
# International License. To view a copy of this license, visit
# https://creativecommons.org/licenses/by/4.0/
"""
Azure RBAC Security Analyzer
=============================
Evaluates Azure Role-Based Access Control (RBAC) assignments and custom role
definitions for security misconfigurations, privilege escalation paths, and
legacy access patterns.

Operates entirely offline on Azure RBAC object dicts — no live Azure API
calls required. All input is passed as plain Python dataclasses or dicts.

Check IDs
----------
AZ-RBAC-001   Owner / Contributor / User Access Administrator at subscription
              scope without PIM (direct permanent assignment)
AZ-RBAC-002   Classic administrator role (legacy Service Admin / Co-Admin)
AZ-RBAC-003   Service principal with Owner role
AZ-RBAC-004   Guest user with a privileged role
AZ-RBAC-005   Privileged direct assignment to a User without PIM at any scope
AZ-RBAC-006   Custom role that grants wildcard (*) actions
AZ-RBAC-007   Assignment at management-group root scope

Usage::

    from analyzers.azure_rbac_analyzer import (
        AzureRBACAnalyzer,
        AzureRoleAssignment,
        AzureCustomRole,
    )

    assignments = [
        AzureRoleAssignment(
            assignment_id="ra-001",
            principal_name="alice@contoso.com",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/abc123",
            is_pim_eligible=False,
        )
    ]
    analyzer = AzureRBACAnalyzer()
    result = analyzer.analyze(assignments)
    print(result.summary())
    for f in result.findings:
        print(f.to_dict())
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AzureRBACseverity(str, Enum):
    """Severity levels for RBAC findings, ordered from most to least severe."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# Input data models
# ---------------------------------------------------------------------------

@dataclass
class AzureRoleAssignment:
    """
    Represents a single Azure RBAC role assignment.

    Attributes:
        assignment_id:    Unique identifier for this role assignment.
        principal_name:   Display name or UPN of the principal.
        principal_type:   "User", "Group", or "ServicePrincipal".
        role_name:        The role being granted, e.g. "Owner", "Contributor".
        scope:            ARM resource path the role is scoped to.
        is_classic_admin: True if this is a legacy Service Admin / Co-Admin.
        is_pim_eligible:  True if the assignment is PIM-eligible (not active).
        principal_is_guest: True if the principal is a B2B guest user.
    """
    assignment_id:      str
    principal_name:     str
    principal_type:     str          # "User" | "Group" | "ServicePrincipal"
    role_name:          str
    scope:              str
    is_classic_admin:   bool = False
    is_pim_eligible:    bool = False  # True = PIM-eligible only, not permanent
    principal_is_guest: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "assignment_id":      self.assignment_id,
            "principal_name":     self.principal_name,
            "principal_type":     self.principal_type,
            "role_name":          self.role_name,
            "scope":              self.scope,
            "is_classic_admin":   self.is_classic_admin,
            "is_pim_eligible":    self.is_pim_eligible,
            "principal_is_guest": self.principal_is_guest,
        }


@dataclass
class AzureCustomRole:
    """
    Represents an Azure custom RBAC role definition.

    Attributes:
        role_id:     Unique identifier for the custom role.
        role_name:   Human-readable role name.
        actions:     List of allowed ARM action strings, e.g. ["*"].
        not_actions: List of excluded action strings.
        scope:       Assignment scope for the custom role definition.
    """
    role_id:     str
    role_name:   str
    actions:     List[str]
    not_actions: List[str] = field(default_factory=list)
    scope:       str       = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "role_id":     self.role_id,
            "role_name":   self.role_name,
            "actions":     list(self.actions),
            "not_actions": list(self.not_actions),
            "scope":       self.scope,
        }


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class AzureRBACFinding:
    """
    A single Azure RBAC security finding.

    Attributes:
        check_id:       AZ-RBAC-XXX identifier.
        severity:       Finding severity.
        principal_name: Name of the principal involved.
        principal_type: Type of the principal involved.
        role_name:      Role name relevant to this finding.
        scope:          ARM scope relevant to this finding.
        message:        Human-readable description of the problem.
        recommendation: Recommended remediation action.
    """
    check_id:       str
    severity:       AzureRBACseverity
    principal_name: str
    principal_type: str
    role_name:      str
    scope:          str
    message:        str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "check_id":       self.check_id,
            "severity":       self.severity.value,
            "principal_name": self.principal_name,
            "principal_type": self.principal_type,
            "role_name":      self.role_name,
            "scope":          self.scope,
            "message":        self.message,
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class AzureRBACResult:
    """
    Aggregated result of an Azure RBAC security analysis run.

    Attributes:
        findings:     All findings produced by the analyzer.
        risk_score:   Aggregate risk score 0–100 (sum of unique fired check weights).
        generated_at: Unix timestamp when the result was created.
    """
    findings:     List[AzureRBACFinding] = field(default_factory=list)
    risk_score:   int                    = 0
    generated_at: float                  = field(default_factory=time.time)

    def summary(self) -> str:
        """Return a one-line human-readable summary of this result."""
        counts = self.by_severity()
        critical = counts.get("CRITICAL", [])
        high     = counts.get("HIGH", [])
        medium   = counts.get("MEDIUM", [])
        low      = counts.get("LOW", [])
        return (
            f"Azure RBAC Report: {len(self.findings)} finding(s), "
            f"risk_score={self.risk_score}, "
            f"CRITICAL={len(critical)}, "
            f"HIGH={len(high)}, "
            f"MEDIUM={len(medium)}, "
            f"LOW={len(low)}"
        )

    def by_severity(self) -> Dict[str, List[AzureRBACFinding]]:
        """Group findings by severity label. Returns dict with severity keys."""
        result: Dict[str, List[AzureRBACFinding]] = {}
        for f in self.findings:
            key = f.severity.value
            result.setdefault(key, []).append(f)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full result to a plain dictionary."""
        counts = self.by_severity()
        return {
            "risk_score":   self.risk_score,
            "generated_at": self.generated_at,
            "total":        len(self.findings),
            "critical":     len(counts.get("CRITICAL", [])),
            "high":         len(counts.get("HIGH", [])),
            "medium":       len(counts.get("MEDIUM", [])),
            "low":          len(counts.get("LOW", [])),
            "findings":     [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Check weights
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "AZ-RBAC-001": 40,  # Owner/Contributor at sub scope without PIM — CRITICAL
    "AZ-RBAC-002": 25,  # Classic admin role                          — HIGH
    "AZ-RBAC-003": 35,  # Service principal with Owner                — CRITICAL
    "AZ-RBAC-004": 25,  # Guest user with privileged role             — HIGH
    "AZ-RBAC-005": 20,  # Privileged direct assignment without PIM    — HIGH
    "AZ-RBAC-006": 15,  # Custom role with wildcard actions           — MEDIUM
    "AZ-RBAC-007": 40,  # Management group root scope assignment      — CRITICAL
}

# Roles considered "privileged" for subscription-scope / PIM checks
_PRIVILEGED_ROLES = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
})

# Roles considered "privileged" for guest-user check (broader set)
_GUEST_PRIVILEGED_ROLES = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Security Admin",
    "Global Administrator",
})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_subscription_scope(scope: str) -> bool:
    """
    Return True when the scope is at subscription level (not resource-group
    or resource level).

    A subscription scope looks like:
        /subscriptions/<sub-id>

    A resource-group scope looks like:
        /subscriptions/<sub-id>/resourceGroups/<rg-name>

    We determine the level by counting the non-empty path segments:
    subscription-level has exactly 2 segments  ("/subscriptions/<id>").
    """
    if not scope.startswith("/subscriptions/"):
        return False
    # Strip leading slash, split, filter empty strings
    parts = [p for p in scope.split("/") if p]
    # ["subscriptions", "<sub-id>"] → 2 parts → subscription scope
    return len(parts) <= 2


def _is_management_group_scope(scope: str) -> bool:
    """Return True when the scope is at the management-group level."""
    return scope.startswith("/providers/Microsoft.Management/managementGroups/")


# ---------------------------------------------------------------------------
# AzureRBACAnalyzer
# ---------------------------------------------------------------------------

class AzureRBACAnalyzer:
    """
    Analyze Azure RBAC assignments and custom role definitions for security
    misconfigurations.

    All analysis is performed offline — no Azure API calls are made.

    Example::

        analyzer = AzureRBACAnalyzer()
        result = analyzer.analyze(assignments, custom_roles=custom_roles)
        print(result.summary())
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        assignments: List[AzureRoleAssignment],
        custom_roles: Optional[List[AzureCustomRole]] = None,
    ) -> AzureRBACResult:
        """
        Analyze a set of Azure RBAC assignments (and optionally custom roles).

        Args:
            assignments:  List of AzureRoleAssignment objects to evaluate.
            custom_roles: Optional list of AzureCustomRole definitions to
                          evaluate alongside the assignments.

        Returns:
            AzureRBACResult containing all findings and a risk score.
        """
        findings: List[AzureRBACFinding] = []

        # Per-assignment checks
        for assignment in assignments:
            findings.extend(self._check_az_rbac_001(assignment))
            findings.extend(self._check_az_rbac_002(assignment))
            findings.extend(self._check_az_rbac_003(assignment))
            findings.extend(self._check_az_rbac_004(assignment))
            findings.extend(self._check_az_rbac_005(assignment))
            findings.extend(self._check_az_rbac_007(assignment))

        # Per-custom-role checks
        for role in (custom_roles or []):
            findings.extend(self._check_az_rbac_006(role))

        # Risk score: sum of weights for each unique fired check ID, cap at 100
        fired_checks = {f.check_id for f in findings}
        risk_score   = min(100, sum(_CHECK_WEIGHTS.get(c, 0) for c in fired_checks))

        return AzureRBACResult(findings=findings, risk_score=risk_score)

    def analyze_many(
        self,
        assignment_sets: List[List[AzureRoleAssignment]],
        custom_role_sets: Optional[List[Optional[List[AzureCustomRole]]]] = None,
    ) -> List[AzureRBACResult]:
        """
        Analyze multiple independent sets of RBAC assignments in one call.

        Args:
            assignment_sets:  A list where each element is a list of
                              AzureRoleAssignment objects representing one
                              analysis scope (e.g. one subscription).
            custom_role_sets: Optional parallel list of custom-role lists,
                              one per assignment set. None entries are allowed.

        Returns:
            A list of AzureRBACResult objects, one per input set.
        """
        results: List[AzureRBACResult] = []
        role_sets: List[Optional[List[AzureCustomRole]]] = (
            custom_role_sets if custom_role_sets is not None
            else [None] * len(assignment_sets)
        )
        for assignments, custom_roles in zip(assignment_sets, role_sets):
            results.append(self.analyze(assignments, custom_roles=custom_roles))
        return results

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    def _check_az_rbac_001(
        self, a: AzureRoleAssignment
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-001: Owner / Contributor / UAA at subscription scope without PIM.

        Permanent (non-PIM) privileged role assignments at the subscription
        level present the highest blast radius risk in Azure. Assignments
        scoped to resource groups or lower are not flagged by this check.
        """
        if (
            a.role_name in _PRIVILEGED_ROLES
            and _is_subscription_scope(a.scope)
            and not a.is_pim_eligible
        ):
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-001",
                severity       = AzureRBACseverity.CRITICAL,
                principal_name = a.principal_name,
                principal_type = a.principal_type,
                role_name      = a.role_name,
                scope          = a.scope,
                message        = (
                    f"Principal '{a.principal_name}' holds the '{a.role_name}' role "
                    f"at subscription scope '{a.scope}' as a direct (non-PIM) "
                    f"permanent assignment. This grants unrestricted subscription-wide "
                    f"access at all times."
                ),
                recommendation = (
                    "Convert this assignment to a PIM eligible assignment and "
                    "require approval + justification for activation. If permanent "
                    "access is needed, restrict the scope to a resource group."
                ),
            )]
        return []

    def _check_az_rbac_002(
        self, a: AzureRoleAssignment
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-002: Classic administrator role detected.

        Classic Service Administrator and Co-Administrator roles are legacy
        Azure constructs that predate ARM RBAC. They cannot be managed through
        PIM and bypass many modern RBAC controls.
        """
        if a.is_classic_admin:
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-002",
                severity       = AzureRBACseverity.HIGH,
                principal_name = a.principal_name,
                principal_type = a.principal_type,
                role_name      = a.role_name,
                scope          = a.scope,
                message        = (
                    f"Principal '{a.principal_name}' has a classic administrator "
                    f"role (Service Administrator / Co-Administrator). These legacy "
                    f"roles bypass Azure RBAC and cannot be governed by PIM."
                ),
                recommendation = (
                    "Migrate classic administrator rights to equivalent ARM RBAC "
                    "roles (e.g. Owner or Contributor) and remove the classic "
                    "assignment. Use the Azure portal under "
                    "'Subscriptions > Access control (IAM) > Classic administrators'."
                ),
            )]
        return []

    def _check_az_rbac_003(
        self, a: AzureRoleAssignment
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-003: Service principal with Owner role.

        Granting Owner to a service principal creates a non-human identity
        with full subscription control and the ability to grant further access,
        enabling privilege escalation if the SP credentials are compromised.
        """
        if a.principal_type == "ServicePrincipal" and a.role_name == "Owner":
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-003",
                severity       = AzureRBACseverity.CRITICAL,
                principal_name = a.principal_name,
                principal_type = a.principal_type,
                role_name      = a.role_name,
                scope          = a.scope,
                message        = (
                    f"Service principal '{a.principal_name}' has the Owner role "
                    f"at scope '{a.scope}'. A compromised service principal with "
                    f"Owner rights can escalate privileges, create backdoor accounts, "
                    f"and exfiltrate data across the entire scope."
                ),
                recommendation = (
                    "Replace the Owner assignment with the least-privilege role "
                    "required for the workload (e.g. Contributor without "
                    "Microsoft.Authorization/*). Apply resource-group or resource "
                    "scope rather than subscription scope where possible."
                ),
            )]
        return []

    def _check_az_rbac_004(
        self, a: AzureRoleAssignment
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-004: Guest user with a privileged role.

        B2B guest accounts are governed by the home tenant, not the resource
        tenant. Assigning them privileged roles significantly increases the
        attack surface and reduces visibility into their activity.
        """
        if a.principal_is_guest and a.role_name in _GUEST_PRIVILEGED_ROLES:
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-004",
                severity       = AzureRBACseverity.HIGH,
                principal_name = a.principal_name,
                principal_type = a.principal_type,
                role_name      = a.role_name,
                scope          = a.scope,
                message        = (
                    f"Guest user '{a.principal_name}' holds the privileged role "
                    f"'{a.role_name}' at scope '{a.scope}'. Guest accounts are "
                    f"managed by an external tenant and may not comply with your "
                    f"organization's MFA or identity governance policies."
                ),
                recommendation = (
                    "Remove the privileged role from the guest account. If external "
                    "collaboration is required, use a time-limited PIM eligible "
                    "assignment with approval workflow, or convert the collaboration "
                    "model to use Azure Lighthouse for cross-tenant access."
                ),
            )]
        return []

    def _check_az_rbac_005(
        self, a: AzureRoleAssignment
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-005: Privileged direct assignment to a User without PIM.

        Any User with a permanent (non-PIM) assignment to a privileged role
        at any scope poses a standing privilege risk. AZ-RBAC-001 handles the
        subscription-scope case specifically; this check flags all other direct
        user assignments regardless of scope.
        """
        if (
            a.role_name in _PRIVILEGED_ROLES
            and not a.is_pim_eligible
            and a.principal_type == "User"
        ):
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-005",
                severity       = AzureRBACseverity.HIGH,
                principal_name = a.principal_name,
                principal_type = a.principal_type,
                role_name      = a.role_name,
                scope          = a.scope,
                message        = (
                    f"User '{a.principal_name}' has a permanent (non-PIM) assignment "
                    f"of the '{a.role_name}' role at scope '{a.scope}'. Standing "
                    f"privileged access increases the window of exposure if the "
                    f"account is compromised."
                ),
                recommendation = (
                    "Replace the permanent assignment with a PIM eligible assignment. "
                    "Require activation with MFA, a justification, and optionally "
                    "manager approval. Set an appropriate maximum activation duration "
                    "(e.g. 4–8 hours)."
                ),
            )]
        return []

    def _check_az_rbac_006(
        self, role: AzureCustomRole
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-006: Custom role with wildcard (*) actions.

        A custom role that grants "*" in its actions list is functionally
        equivalent to the built-in Owner role for the resources in its scope,
        eliminating any benefit of a custom role definition.
        """
        if "*" in role.actions:
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-006",
                severity       = AzureRBACseverity.MEDIUM,
                principal_name = "",          # role-level finding, no single principal
                principal_type = "",
                role_name      = role.role_name,
                scope          = role.scope,
                message        = (
                    f"Custom role '{role.role_name}' (ID: {role.role_id}) includes "
                    f"'*' in its actions list, granting all resource provider actions "
                    f"at scope '{role.scope}'. This negates the least-privilege "
                    f"purpose of a custom role."
                ),
                recommendation = (
                    "Replace the wildcard '*' with the specific action strings "
                    "required by the workload. Use the Azure resource provider "
                    "operations reference to enumerate only the needed permissions. "
                    "Apply NotActions to exclude sensitive operations such as "
                    "Microsoft.Authorization/*/write."
                ),
            )]
        return []

    def _check_az_rbac_007(
        self, a: AzureRoleAssignment
    ) -> List[AzureRBACFinding]:
        """
        AZ-RBAC-007: Assignment at management-group root scope.

        Assignments scoped to the root management group affect every
        subscription and resource in the entire Azure tenant. Even Reader
        assignments at this level carry significant data exposure risk.
        """
        if _is_management_group_scope(a.scope):
            return [AzureRBACFinding(
                check_id       = "AZ-RBAC-007",
                severity       = AzureRBACseverity.CRITICAL,
                principal_name = a.principal_name,
                principal_type = a.principal_type,
                role_name      = a.role_name,
                scope          = a.scope,
                message        = (
                    f"Principal '{a.principal_name}' has the '{a.role_name}' role "
                    f"assigned at management-group scope '{a.scope}'. Management-group "
                    f"assignments cascade to all subscriptions and resource groups in "
                    f"the tenant."
                ),
                recommendation = (
                    "Move the assignment to the narrowest scope that satisfies the "
                    "business requirement (subscription or resource group). If "
                    "management-group scope is unavoidable, use PIM eligibility, "
                    "require approval, and apply Conditional Access policies."
                ),
            )]
        return []
