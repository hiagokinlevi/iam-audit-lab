# privilege_escalation_detector.py
# AWS IAM privilege escalation path detector.
# Identifies IAM roles and policies that contain dangerous permission combinations
# that can be used to escalate privileges — no live AWS API calls required.
#
# Copyright (c) 2026 Cyber Port (github.com/hiagokinlevi)
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See: https://creativecommons.org/licenses/by/4.0/

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Weight table for every check.  risk_score = min(100, sum of fired weights).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "PRIV-ESC-001": 45,  # iam:CreatePolicyVersion — overwrite policy with admin perms
    "PRIV-ESC-002": 45,  # iam:AttachRolePolicy + sts:AssumeRole — attach + assume
    "PRIV-ESC-003": 45,  # iam:PassRole with resource "*" — pass any role to services
    "PRIV-ESC-004": 30,  # iam:CreateLoginProfile — create console password for any user
    "PRIV-ESC-005": 30,  # iam:UpdateLoginProfile — reset any user's console password
    "PRIV-ESC-006": 45,  # lambda:CreateFunction + iam:PassRole — deploy with admin exec role
    "PRIV-ESC-007": 25,  # iam:AddUserToGroup — add user to privileged group
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IAMStatement:
    """Single statement from an IAM policy document.

    Attributes:
        effect:     "Allow" or "Deny".
        actions:    List of IAM action strings, e.g. ["iam:CreatePolicyVersion", "*"].
        resources:  List of resource ARNs or wildcards, e.g. ["*"].
        conditions: IAM condition block; empty dict means unconditional.
    """

    effect: str                         # "Allow" or "Deny"
    actions: List[str]                  # IAM action strings
    resources: List[str]                # resource ARNs / wildcards
    conditions: Dict[str, Any] = field(default_factory=dict)  # condition block

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain Python dictionary."""
        return {
            "effect": self.effect,
            "actions": list(self.actions),
            "resources": list(self.resources),
            "conditions": dict(self.conditions),
        }


@dataclass
class IAMPolicyDoc:
    """Represents a single attached IAM policy document.

    Attributes:
        policy_name: Human-readable name of the policy.
        statements:  Ordered list of IAMStatement objects.
    """

    policy_name: str
    statements: List[IAMStatement] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain Python dictionary."""
        return {
            "policy_name": self.policy_name,
            "statements": [s.to_dict() for s in self.statements],
        }


@dataclass
class IAMRole:
    """Represents an AWS IAM role with its attached policies.

    Attributes:
        role_name: Short role name (e.g. "MyDeployRole").
        role_arn:  Full ARN (e.g. "arn:aws:iam::123456789012:role/MyDeployRole").
        policies:  All policy documents attached to this role.
    """

    role_name: str
    role_arn: str
    policies: List[IAMPolicyDoc] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain Python dictionary."""
        return {
            "role_name": self.role_name,
            "role_arn": self.role_arn,
            "policies": [p.to_dict() for p in self.policies],
        }

    # Convenience: flatten all statements from all attached policies.
    def _all_statements(self) -> List[IAMStatement]:
        stmts: List[IAMStatement] = []
        for policy in self.policies:
            stmts.extend(policy.statements)
        return stmts


@dataclass
class PrivEscFinding:
    """A single privilege escalation finding for one check on one role.

    Attributes:
        check_id:         Canonical identifier, e.g. "PRIV-ESC-001".
        severity:         "CRITICAL", "HIGH", "MEDIUM", or "LOW".
        role_name:        Name of the offending role.
        role_arn:         ARN of the offending role.
        dangerous_actions: The specific IAM actions that triggered this finding.
        message:          Human-readable description of the risk.
        remediation:      Actionable guidance to fix the finding.
    """

    check_id: str
    severity: str
    role_name: str
    role_arn: str
    dangerous_actions: List[str]
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain Python dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "role_name": self.role_name,
            "role_arn": self.role_arn,
            "dangerous_actions": list(self.dangerous_actions),
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class PrivEscResult:
    """Aggregated privilege escalation analysis result for a single role.

    Attributes:
        role_name: Name of the analysed role.
        role_arn:  ARN of the analysed role.
        findings:  All PrivEscFinding objects raised for this role.
        risk_score: Integer 0–100 derived from the sum of fired check weights.
    """

    role_name: str
    role_arn: str
    findings: List[PrivEscFinding] = field(default_factory=list)
    risk_score: int = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of this result."""
        count = len(self.findings)
        if count == 0:
            return (
                f"Role '{self.role_name}': no privilege escalation paths detected "
                f"(risk_score={self.risk_score})."
            )
        sev_map = self.by_severity()
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = sev_map.get(sev, 0)
            if n:
                parts.append(f"{n} {sev}")
        sev_str = ", ".join(parts)
        return (
            f"Role '{self.role_name}': {count} finding(s) [{sev_str}] — "
            f"risk_score={self.risk_score}/100."
        )

    def by_severity(self) -> Dict[str, List[PrivEscFinding]]:
        """Return findings grouped by severity.

        Returns a dict whose keys are severity labels present in *this* result.
        Always returns at least an empty dict (never raises).
        """
        grouped: Dict[str, List[PrivEscFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain Python dictionary."""
        return {
            "role_name": self.role_name,
            "role_arn": self.role_arn,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _action_matches(stmt_action: str, target_action: str) -> bool:
    """Return True if *stmt_action* (from a policy) covers *target_action*.

    Matching rules (case-insensitive):
      1. Exact match: ``"iam:createpolicyversion" == "iam:createpolicyversion"``
      2. Global wildcard: ``"*"`` covers everything.
      3. Service wildcard: ``"iam:*"`` covers any ``"iam:..."`` action.
    """
    sa = stmt_action.lower()
    ta = target_action.lower()

    # Exact match
    if sa == ta:
        return True
    # Global wildcard
    if sa == "*":
        return True
    # Service-level wildcard  e.g. "iam:*" covers "iam:createpolicyversion"
    if sa.endswith(":*") and ta.startswith(sa[:-1]):
        return True
    return False


def _has_action(statements: List[IAMStatement], action: str) -> bool:
    """Return True if at least one Allow statement grants *action*.

    Only Allow statements with a non-empty resource list are evaluated.
    Deny statements are intentionally ignored (the caller is responsible for
    understanding that a separate Deny in a higher-level policy may still block
    the action at runtime; this detector flags *potential* paths, not confirmed
    ones).
    """
    for stmt in statements:
        # Only Allow grants escalation potential.
        if stmt.effect.lower() != "allow":
            continue
        # An empty resource list means the statement is effectively a no-op.
        if not stmt.resources:
            continue
        for stmt_action in stmt.actions:
            if _action_matches(stmt_action, action):
                return True
    return False


def _has_all_actions(statements: List[IAMStatement], actions: List[str]) -> bool:
    """Return True only when every action in *actions* is granted by Allow stmts."""
    return all(_has_action(statements, a) for a in actions)


def _has_passrole_with_wildcard_resource(statements: List[IAMStatement]) -> bool:
    """Return True if iam:PassRole is allowed on resource "*".

    PRIV-ESC-003 specifically requires the resource to be "*" — a scoped
    PassRole (e.g. only a single role ARN) is NOT considered an escalation path.
    """
    for stmt in statements:
        if stmt.effect.lower() != "allow":
            continue
        if not stmt.resources:
            continue
        # Check if this statement grants iam:PassRole (or iam:* / *)
        grants_passrole = any(
            _action_matches(sa, "iam:PassRole") for sa in stmt.actions
        )
        if grants_passrole and "*" in stmt.resources:
            return True
    return False


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class PrivilegeEscalationDetector:
    """Stateless detector that analyses IAM roles for privilege escalation paths.

    All checks are purely static (no AWS API calls).  Each check maps to a
    canonical check ID (PRIV-ESC-001 … PRIV-ESC-007) and a weight used to
    compute the role's aggregate risk_score (capped at 100).

    Usage::

        detector = PrivilegeEscalationDetector()
        result = detector.analyze(role)
        print(result.summary())
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, role: IAMRole) -> PrivEscResult:
        """Analyse a single IAM role and return a PrivEscResult.

        Each of the 7 checks is evaluated independently.  The final
        risk_score is ``min(100, sum of weights for every unique fired check)``.
        """
        stmts = role._all_statements()
        findings: List[PrivEscFinding] = []
        fired_ids: List[str] = []  # preserve insertion order; dedup on IDs

        # Run all checks in order; each appends to *findings* / *fired_ids*.
        self._check_001(role, stmts, findings, fired_ids)
        self._check_002(role, stmts, findings, fired_ids)
        self._check_003(role, stmts, findings, fired_ids)
        self._check_004(role, stmts, findings, fired_ids)
        self._check_005(role, stmts, findings, fired_ids)
        self._check_006(role, stmts, findings, fired_ids)
        self._check_007(role, stmts, findings, fired_ids)

        # Compute risk score from unique fired check IDs.
        unique_ids = list(dict.fromkeys(fired_ids))  # deduplicate, preserve order
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in unique_ids)
        risk_score = min(100, raw_score)

        return PrivEscResult(
            role_name=role.role_name,
            role_arn=role.role_arn,
            findings=findings,
            risk_score=risk_score,
        )

    def analyze_many(self, roles: List[IAMRole]) -> List[PrivEscResult]:
        """Analyse a list of IAM roles and return one PrivEscResult per role."""
        return [self.analyze(role) for role in roles]

    # ------------------------------------------------------------------
    # Individual checks (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _record(
        findings: List[PrivEscFinding],
        fired_ids: List[str],
        check_id: str,
        severity: str,
        role: IAMRole,
        dangerous_actions: List[str],
        message: str,
        remediation: str,
    ) -> None:
        """Append a finding and track the fired check ID."""
        findings.append(
            PrivEscFinding(
                check_id=check_id,
                severity=severity,
                role_name=role.role_name,
                role_arn=role.role_arn,
                dangerous_actions=dangerous_actions,
                message=message,
                remediation=remediation,
            )
        )
        fired_ids.append(check_id)

    # PRIV-ESC-001 — iam:CreatePolicyVersion
    def _check_001(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        if not _has_action(stmts, "iam:CreatePolicyVersion"):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-001",
            severity="CRITICAL",
            role=role,
            dangerous_actions=["iam:CreatePolicyVersion"],
            message=(
                f"Role '{role.role_name}' is allowed iam:CreatePolicyVersion. "
                "An attacker can create a new policy version that grants "
                "AdministratorAccess and set it as the default version, "
                "effectively granting themselves full admin privileges."
            ),
            remediation=(
                "Remove iam:CreatePolicyVersion from the role's policies. "
                "If policy version management is required, restrict it to "
                "specific policy ARNs via resource conditions and require "
                "MFA via a condition key."
            ),
        )

    # PRIV-ESC-002 — iam:AttachRolePolicy + sts:AssumeRole
    def _check_002(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        if not _has_all_actions(stmts, ["iam:AttachRolePolicy", "sts:AssumeRole"]):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-002",
            severity="CRITICAL",
            role=role,
            dangerous_actions=["iam:AttachRolePolicy", "sts:AssumeRole"],
            message=(
                f"Role '{role.role_name}' is allowed both iam:AttachRolePolicy and "
                "sts:AssumeRole. An attacker can attach AdministratorAccess to any "
                "role and then assume that role to gain full admin access."
            ),
            remediation=(
                "Remove iam:AttachRolePolicy from the role. If policy attachment "
                "is required, restrict the resource ARN to specific policies and "
                "roles. Avoid combining policy-management permissions with "
                "sts:AssumeRole on the same role."
            ),
        )

    # PRIV-ESC-003 — iam:PassRole with resource "*"
    def _check_003(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        if not _has_passrole_with_wildcard_resource(stmts):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-003",
            severity="CRITICAL",
            role=role,
            dangerous_actions=["iam:PassRole"],
            message=(
                f"Role '{role.role_name}' is allowed iam:PassRole on resource '*'. "
                "An attacker can pass any highly-privileged role to an AWS service "
                "(EC2, Lambda, ECS, etc.) under their control and execute actions "
                "with that role's permissions."
            ),
            remediation=(
                "Restrict iam:PassRole to specific role ARNs that are required for "
                "the workload. Replace the resource '*' with explicit ARNs. "
                "Consider adding an iam:PassedToService condition key to limit "
                "which AWS services can receive the role."
            ),
        )

    # PRIV-ESC-004 — iam:CreateLoginProfile
    def _check_004(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        if not _has_action(stmts, "iam:CreateLoginProfile"):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-004",
            severity="HIGH",
            role=role,
            dangerous_actions=["iam:CreateLoginProfile"],
            message=(
                f"Role '{role.role_name}' is allowed iam:CreateLoginProfile. "
                "An attacker can create a console login (password) for any IAM user "
                "that currently has no console access — including highly-privileged "
                "users — and log in as that user."
            ),
            remediation=(
                "Remove iam:CreateLoginProfile unless strictly required. "
                "If needed, restrict the resource to specific user ARNs and "
                "require MFA via an aws:MultiFactorAuthPresent condition."
            ),
        )

    # PRIV-ESC-005 — iam:UpdateLoginProfile
    def _check_005(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        if not _has_action(stmts, "iam:UpdateLoginProfile"):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-005",
            severity="HIGH",
            role=role,
            dangerous_actions=["iam:UpdateLoginProfile"],
            message=(
                f"Role '{role.role_name}' is allowed iam:UpdateLoginProfile. "
                "An attacker can reset the console password of any IAM user, "
                "including administrators, and log in as that user."
            ),
            remediation=(
                "Remove iam:UpdateLoginProfile unless strictly required. "
                "If needed, restrict the resource to specific user ARNs and "
                "require MFA via an aws:MultiFactorAuthPresent condition."
            ),
        )

    # PRIV-ESC-006 — lambda:CreateFunction + iam:PassRole
    def _check_006(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        has_lambda_create = _has_action(stmts, "lambda:CreateFunction")
        has_passrole = _has_action(stmts, "iam:PassRole")
        if not (has_lambda_create and has_passrole):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-006",
            severity="CRITICAL",
            role=role,
            dangerous_actions=["lambda:CreateFunction", "iam:PassRole"],
            message=(
                f"Role '{role.role_name}' is allowed both lambda:CreateFunction "
                "and iam:PassRole. An attacker can create a Lambda function that "
                "executes arbitrary code, pass an admin-level execution role to it, "
                "and invoke it to perform privileged actions."
            ),
            remediation=(
                "Remove lambda:CreateFunction or restrict iam:PassRole to specific "
                "Lambda execution role ARNs. Enforce resource-based policies on "
                "Lambda and use iam:PassedToService condition to limit PassRole "
                "to lambda.amazonaws.com only."
            ),
        )

    # PRIV-ESC-007 — iam:AddUserToGroup
    def _check_007(
        self,
        role: IAMRole,
        stmts: List[IAMStatement],
        findings: List[PrivEscFinding],
        fired_ids: List[str],
    ) -> None:
        if not _has_action(stmts, "iam:AddUserToGroup"):
            return
        self._record(
            findings,
            fired_ids,
            check_id="PRIV-ESC-007",
            severity="HIGH",
            role=role,
            dangerous_actions=["iam:AddUserToGroup"],
            message=(
                f"Role '{role.role_name}' is allowed iam:AddUserToGroup. "
                "An attacker can add any IAM user (including themselves, if they "
                "have a user identity) to a highly-privileged group such as "
                "one with AdministratorAccess policies attached."
            ),
            remediation=(
                "Remove iam:AddUserToGroup from the role. If group membership "
                "management is necessary, restrict the resource to specific group "
                "ARNs and consider requiring MFA."
            ),
        )
