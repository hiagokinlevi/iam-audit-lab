"""
IAM Permission Boundary Analyzer
===================================
Analyzes AWS IAM users and roles for missing or misconfigured permission
boundaries. Permission boundaries are an advanced IAM feature that set the
maximum permissions an identity-based policy can grant, preventing privilege
escalation even if a principal is over-permissioned.

Checks Performed
-----------------
PB-001  No permission boundary set
        The principal has no permission boundary attached. Any policy that
        grants administrative permissions has no safety cap.

PB-002  Boundary allows wildcard actions
        The permission boundary grants ``*`` or ``<service>:*`` for
        sensitive services (iam, sts, organizations, kms). A boundary
        granting unrestricted IAM actions provides no protection against
        privilege escalation.

PB-003  Boundary not enforced in role trust policy
        For cross-account assume-role patterns, the trust policy does not
        require the caller to have a permission boundary. An attacker who
        can assume the role without boundary enforcement can escalate
        privileges.

PB-004  Boundary references deleted / non-existent policy
        The boundary ARN does not correspond to a known managed policy in
        the account. This is an inert boundary that provides no protection.

PB-005  Overly permissive boundary (>25 distinct allow-actions)
        The boundary policy allows more than 25 distinct IAM/KMS/STS
        actions, suggesting that the boundary was copied from a permissive
        policy rather than designed as a cap.

Usage::

    from analyzers.permission_boundary.analyzer import (
        PermissionBoundaryAnalyzer,
        BoundaryReport,
    )

    analyzer = PermissionBoundaryAnalyzer()
    report = analyzer.analyze(principals, known_policy_arns=known_arns)
    print(report.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BoundarySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Check definitions
# ---------------------------------------------------------------------------

_CHECK_META: dict[str, tuple[BoundarySeverity, str]] = {
    "PB-001": (BoundarySeverity.HIGH,     "No permission boundary attached"),
    "PB-002": (BoundarySeverity.CRITICAL, "Boundary allows wildcard sensitive actions"),
    "PB-003": (BoundarySeverity.MEDIUM,   "Boundary not enforced in trust policy"),
    "PB-004": (BoundarySeverity.HIGH,     "Boundary references non-existent policy"),
    "PB-005": (BoundarySeverity.MEDIUM,   "Overly permissive boundary (>25 allow-actions)"),
}

_CHECK_WEIGHTS: dict[str, int] = {
    "PB-001": 20,
    "PB-002": 35,
    "PB-003": 15,
    "PB-004": 25,
    "PB-005": 10,
}

# Sensitive services — wildcard grants on these are especially dangerous
_SENSITIVE_SERVICES = {"iam", "sts", "organizations", "kms", "secretsmanager", "ssm"}

# Max distinct allow-actions before flagging as overly permissive
_MAX_ALLOW_ACTIONS = 25


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BoundaryFinding:
    """
    A single permission boundary finding for one principal.

    Attributes:
        check_id:       Check identifier (PB-001 … PB-005).
        severity:       Finding severity.
        title:          Short description.
        detail:         Detailed explanation.
        remediation:    Step to fix the issue.
        principal_arn:  ARN of the IAM principal affected.
        principal_type: ``user`` or ``role``.
    """
    check_id:       str
    severity:       BoundarySeverity
    title:          str
    detail:         str
    remediation:    str
    principal_arn:  str = ""
    principal_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id":       self.check_id,
            "severity":       self.severity.value,
            "title":          self.title,
            "detail":         self.detail,
            "remediation":    self.remediation,
            "principal_arn":  self.principal_arn,
            "principal_type": self.principal_type,
        }


@dataclass
class PrincipalBoundaryPosture:
    """
    Boundary posture of a single IAM principal.

    Attributes:
        principal_arn:   ARN of the IAM user or role.
        principal_type:  ``user`` or ``role``.
        boundary_arn:    ARN of the attached boundary policy (empty if none).
        findings:        List of BoundaryFindings for this principal.
        risk_score:      Aggregate 0–100 risk score.
    """
    principal_arn:  str
    principal_type: str = "unknown"
    boundary_arn:   str = ""
    findings:       list[BoundaryFinding] = field(default_factory=list)
    risk_score:     int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == BoundarySeverity.CRITICAL)

    def posture_summary(self) -> str:
        return (
            f"[{self.principal_type.upper()}] {self.principal_arn} | "
            f"boundary={'<none>' if not self.boundary_arn else self.boundary_arn} | "
            f"risk={self.risk_score} | {self.finding_count} finding(s)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_arn":  self.principal_arn,
            "principal_type": self.principal_type,
            "boundary_arn":   self.boundary_arn,
            "finding_count":  self.finding_count,
            "risk_score":     self.risk_score,
            "findings":       [f.to_dict() for f in self.findings],
        }


@dataclass
class BoundaryReport:
    """
    Aggregated permission boundary report across all principals.

    Attributes:
        postures:          Per-principal posture results.
        total_principals:  Total principals analyzed.
        unprotected_count: Principals with no boundary (PB-001).
        all_findings:      Flat list of all findings.
    """
    postures:          list[PrincipalBoundaryPosture] = field(default_factory=list)
    total_principals:  int = 0
    unprotected_count: int = 0
    all_findings:      list[BoundaryFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def critical_findings(self) -> list[BoundaryFinding]:
        return [f for f in self.all_findings if f.severity == BoundarySeverity.CRITICAL]

    def findings_by_check(self, check_id: str) -> list[BoundaryFinding]:
        return [f for f in self.all_findings if f.check_id == check_id]

    def findings_by_severity(self, severity: BoundarySeverity) -> list[BoundaryFinding]:
        return [f for f in self.all_findings if f.severity == severity]

    def summary(self) -> str:
        return (
            f"BoundaryReport: {self.total_principals} principal(s) | "
            f"{self.unprotected_count} unprotected | "
            f"{self.total_findings} finding(s) "
            f"[CRITICAL={len(self.critical_findings)}]"
        )


# ---------------------------------------------------------------------------
# PermissionBoundaryAnalyzer
# ---------------------------------------------------------------------------

class PermissionBoundaryAnalyzer:
    """
    Analyzes IAM users and roles for permission boundary gaps.

    Principal dicts support AWS SDK-style key names (PascalCase) and
    lowercase snake_case equivalents.

    Expected principal keys:
      - Arn / arn
      - Type / type  (``user`` or ``role``)
      - PermissionsBoundary / permissions_boundary
          - PermissionsBoundaryArn / permissions_boundary_arn
      - PermissionsBoundaryDocument / permissions_boundary_document
          - Statement list (standard IAM policy document)
      - AssumeRolePolicyDocument / assume_role_policy_document
          (roles only — trust policy)

    Args:
        require_boundary_on_all: If True, every principal without a boundary
            triggers PB-001 (default True). Set to False to suppress PB-001
            for service-linked roles and AWS-managed principals.
        ignore_aws_managed: If True, skip principals whose ARN starts with
            ``arn:aws:iam::aws:`` (AWS-managed service roles).
    """

    def __init__(
        self,
        require_boundary_on_all: bool = True,
        ignore_aws_managed: bool = True,
    ) -> None:
        self._require_boundary_on_all = require_boundary_on_all
        self._ignore_aws_managed = ignore_aws_managed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_principal(
        self,
        principal: dict[str, Any],
        known_policy_arns: Optional[set[str]] = None,
    ) -> PrincipalBoundaryPosture:
        """
        Analyze a single principal dict.

        Args:
            principal:          IAM principal dict.
            known_policy_arns:  Set of valid managed policy ARNs in the account.
                                If provided, enables PB-004 check.

        Returns a PrincipalBoundaryPosture.
        """
        arn  = _get(principal, "Arn", "arn", default="")
        ptype = _get(principal, "Type", "type", default="unknown")

        # Skip AWS-managed service roles
        if self._ignore_aws_managed and arn.startswith("arn:aws:iam::aws:"):
            return PrincipalBoundaryPosture(principal_arn=arn, principal_type=ptype)

        boundary_block = _get(
            principal, "PermissionsBoundary", "permissions_boundary", default=None
        )
        boundary_arn = ""
        if isinstance(boundary_block, dict):
            boundary_arn = _get(
                boundary_block,
                "PermissionsBoundaryArn", "permissions_boundary_arn",
                default="",
            ) or ""
        elif isinstance(boundary_block, str):
            boundary_arn = boundary_block

        posture = PrincipalBoundaryPosture(
            principal_arn=arn,
            principal_type=ptype,
            boundary_arn=boundary_arn,
        )

        findings: list[BoundaryFinding] = []

        # PB-001: No boundary
        if not boundary_arn:
            if self._require_boundary_on_all:
                findings.append(self._make_finding(
                    "PB-001", arn, ptype,
                    detail=(
                        f"Principal '{arn}' has no permission boundary attached. "
                        "Any policy granting administrative access has no safety cap, "
                        "enabling privilege escalation if the identity is compromised."
                    ),
                    remediation=(
                        "Attach a permission boundary: "
                        "`aws iam put-user-permissions-boundary --user-name <name> "
                        "--permissions-boundary <boundary-policy-arn>` or equivalent "
                        "for roles."
                    ),
                ))
        else:
            # PB-004: Boundary ARN not in known policies
            if known_policy_arns is not None and boundary_arn not in known_policy_arns:
                findings.append(self._make_finding(
                    "PB-004", arn, ptype,
                    detail=(
                        f"The permission boundary '{boundary_arn}' attached to "
                        f"'{arn}' does not correspond to a known managed policy "
                        "in this account. The boundary is inert and provides no "
                        "protection."
                    ),
                    remediation=(
                        "Verify the boundary policy exists and re-attach a valid "
                        "boundary: `aws iam list-policies --scope Local`"
                    ),
                ))

            # PB-002: Boundary allows wildcard sensitive actions
            boundary_doc = _get(
                principal,
                "PermissionsBoundaryDocument", "permissions_boundary_document",
                default=None,
            )
            if boundary_doc:
                wild_actions = _find_wildcard_sensitive_actions(boundary_doc)
                if wild_actions:
                    findings.append(self._make_finding(
                        "PB-002", arn, ptype,
                        detail=(
                            f"The permission boundary for '{arn}' allows wildcard "
                            f"actions on sensitive services: {sorted(wild_actions)}. "
                            "A boundary granting unrestricted IAM/STS/KMS actions "
                            "offers no protection against privilege escalation."
                        ),
                        remediation=(
                            "Replace wildcard grants with explicit action lists in the "
                            "boundary policy and remove all sensitive-service wildcards."
                        ),
                    ))

                # PB-005: Overly permissive boundary
                allow_actions = _count_allow_actions(boundary_doc)
                if allow_actions > _MAX_ALLOW_ACTIONS:
                    findings.append(self._make_finding(
                        "PB-005", arn, ptype,
                        detail=(
                            f"The permission boundary for '{arn}' allows "
                            f"{allow_actions} distinct actions — exceeding the "
                            f"{_MAX_ALLOW_ACTIONS}-action threshold. The boundary "
                            "appears to be a copy of a permissive policy rather "
                            "than a targeted cap."
                        ),
                        remediation=(
                            "Redesign the boundary policy to allow only the minimum "
                            "set of actions required by the workload."
                        ),
                    ))

        # PB-003: Trust policy does not enforce boundary (roles only)
        if ptype == "role" and boundary_arn:
            trust_doc = _get(
                principal,
                "AssumeRolePolicyDocument", "assume_role_policy_document",
                default=None,
            )
            if trust_doc and not _trust_enforces_boundary(trust_doc):
                findings.append(self._make_finding(
                    "PB-003", arn, ptype,
                    detail=(
                        f"The trust policy for role '{arn}' does not require "
                        "callers to have a permission boundary condition. "
                        "Cross-account or federated principals can assume this "
                        "role without boundary enforcement."
                    ),
                    remediation=(
                        "Add a condition to the trust policy requiring "
                        "`iam:PermissionsBoundary` on the assuming principal, or "
                        "restrict the trust policy to principals already governed "
                        "by a boundary."
                    ),
                ))

        posture.findings = findings
        posture.risk_score = min(100, sum(
            _CHECK_WEIGHTS.get(f.check_id, 5) for f in findings
        ))
        return posture

    def analyze(
        self,
        principals: list[dict[str, Any]],
        known_policy_arns: Optional[set[str]] = None,
    ) -> BoundaryReport:
        """
        Analyze a list of IAM principals.

        Returns a BoundaryReport aggregating all findings.
        """
        postures: list[PrincipalBoundaryPosture] = []
        all_findings: list[BoundaryFinding] = []
        unprotected = 0

        for p in principals:
            posture = self.analyze_principal(p, known_policy_arns)
            postures.append(posture)
            all_findings.extend(posture.findings)
            if not posture.boundary_arn:
                unprotected += 1

        return BoundaryReport(
            postures=postures,
            total_principals=len(principals),
            unprotected_count=unprotected,
            all_findings=all_findings,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding(
        check_id: str,
        arn: str,
        ptype: str,
        detail: str,
        remediation: str,
    ) -> BoundaryFinding:
        severity, title = _CHECK_META[check_id]
        return BoundaryFinding(
            check_id=check_id,
            severity=severity,
            title=title,
            detail=detail,
            remediation=remediation,
            principal_arn=arn,
            principal_type=ptype,
        )


# ---------------------------------------------------------------------------
# Policy document helpers
# ---------------------------------------------------------------------------

def _find_wildcard_sensitive_actions(doc: dict[str, Any]) -> set[str]:
    """Return set of sensitive wildcard action strings found in Allow statements."""
    results: set[str] = set()
    for stmt in _statements(doc):
        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            action_lower = action.lower()
            if action_lower == "*":
                results.add("*")
            elif action_lower.endswith(":*"):
                service = action_lower.split(":")[0]
                if service in _SENSITIVE_SERVICES:
                    results.add(action_lower)
    return results


def _count_allow_actions(doc: dict[str, Any]) -> int:
    """Count distinct explicit Allow actions in a policy document."""
    actions: set[str] = set()
    for stmt in _statements(doc):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        for a in raw:
            if a != "*" and not a.endswith(":*"):
                actions.add(a.lower())
    return len(actions)


def _trust_enforces_boundary(doc: dict[str, Any]) -> bool:
    """
    Return True if any statement in the trust policy includes a
    condition that references iam:PermissionsBoundary.
    """
    for stmt in _statements(doc):
        condition = stmt.get("Condition", {})
        condition_str = str(condition).lower()
        if "permissionsboundary" in condition_str:
            return True
    return False


def _statements(doc: Any) -> list[dict[str, Any]]:
    """Extract Statement list from a policy document."""
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    return stmts if isinstance(stmts, list) else []


def _get(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return default
