"""
AWS Service Control Policy (SCP) Analyzer
===========================================
Evaluates AWS Organizations Service Control Policies for security gaps:
missing guardrails, overly permissive allow statements, absence of critical
deny controls, and wildcard resource grants.

Operates on parsed SCP policy documents (dict format — same structure as
IAM policy JSON). No live AWS API calls required.

Check IDs
----------
SCP-001   SCP allows all actions (Effect:Allow Action:*)
SCP-002   Missing critical security guardrail: no Deny for root account usage
SCP-003   Missing critical security guardrail: no Deny for disabling CloudTrail
SCP-004   Missing critical security guardrail: no Deny for leaving AWS Organizations
SCP-005   SCP allows access to all resources (Resource:*)
SCP-006   No SCPs attached (policy list is empty)
SCP-007   SCP statement with NotAction — implicit allow of broad action set

Usage::

    from analyzers.scp_analyzer import SCPAnalyzer, SCPDocument

    doc = SCPDocument(
        name="FullAWSAccess",
        statements=[{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    )
    analyzer = SCPAnalyzer()
    report = analyzer.analyze([doc])
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SCPSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# SCPDocument — input model
# ---------------------------------------------------------------------------

@dataclass
class SCPDocument:
    """
    A single SCP policy document.

    Attributes:
        name:       Policy name or identifier.
        statements: List of policy statement dicts (IAM statement format).
        target:     Organizational unit / account this SCP is attached to.
    """
    name:       str
    statements: List[Dict] = field(default_factory=list)
    target:     str        = ""

    @classmethod
    def from_policy_document(cls, name: str, document: Dict, target: str = "") -> "SCPDocument":
        """Create from a full IAM-style policy document dict."""
        stmts = document.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        return cls(name=name, statements=stmts, target=target)


# ---------------------------------------------------------------------------
# SCPFinding
# ---------------------------------------------------------------------------

@dataclass
class SCPFinding:
    """
    A single SCP security finding.

    Attributes:
        check_id:    SCP-XXX identifier.
        severity:    Severity level.
        policy_name: Name of the SCP that triggered the finding.
        title:       Short description.
        detail:      Detailed explanation.
        evidence:    The specific statement or value that triggered the check.
        remediation: Recommended fix.
    """
    check_id:    str
    severity:    SCPSeverity
    policy_name: str
    title:       str
    detail:      str
    evidence:    str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "policy_name": self.policy_name,
            "title":       self.title,
            "detail":      self.detail,
            "evidence":    self.evidence[:512],
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        return f"[{self.check_id}] {self.severity.value}: {self.title} ({self.policy_name})"


# ---------------------------------------------------------------------------
# SCPReport
# ---------------------------------------------------------------------------

@dataclass
class SCPReport:
    """
    Aggregated SCP analysis report.

    Attributes:
        findings:          All SCP findings.
        risk_score:        0–100 aggregate risk score.
        policies_analyzed: Number of SCP documents analyzed.
        generated_at:      Unix timestamp.
    """
    findings:          List[SCPFinding] = field(default_factory=list)
    risk_score:        int              = 0
    policies_analyzed: int              = 0
    generated_at:      float            = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> List[SCPFinding]:
        return [f for f in self.findings if f.severity == SCPSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[SCPFinding]:
        return [f for f in self.findings if f.severity == SCPSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> List[SCPFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_policy(self, name: str) -> List[SCPFinding]:
        return [f for f in self.findings if f.policy_name == name]

    def summary(self) -> str:
        return (
            f"SCP Report: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"critical={len(self.critical_findings)}, "
            f"policies_analyzed={self.policies_analyzed}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings":    self.total_findings,
            "risk_score":        self.risk_score,
            "critical":          len(self.critical_findings),
            "high":              len(self.high_findings),
            "policies_analyzed": self.policies_analyzed,
            "generated_at":      self.generated_at,
            "findings":          [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Check weights
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "SCP-001": 40,
    "SCP-002": 45,
    "SCP-003": 40,
    "SCP-004": 35,
    "SCP-005": 30,
    "SCP-006": 35,
    "SCP-007": 25,
}

# Critical guardrails: action prefixes that should be denied
_CRITICAL_GUARDRAILS = {
    "SCP-002": {
        "title": "No Deny for AWS root account usage",
        "actions": {"aws:*", "sts:AssumeRoot", "*"},
        "condition_key": "aws:PrincipalType",
        "condition_value": "Root",
        "description": (
            "No SCP Deny statement restricts root account usage. "
            "Root account actions should be denied except for specific "
            "break-glass scenarios."
        ),
        "remediation": (
            "Add a Deny statement with Condition: "
            "StringEquals: aws:PrincipalType: Root to prevent root account "
            "API usage across the organization."
        ),
    },
    "SCP-003": {
        "title": "No Deny for disabling CloudTrail",
        "actions": {
            "cloudtrail:DeleteTrail",
            "cloudtrail:StopLogging",
            "cloudtrail:UpdateTrail",
            "cloudtrail:*",
        },
        "description": (
            "No SCP Deny statement prevents disabling CloudTrail logging. "
            "Attackers commonly disable audit logging to cover their tracks."
        ),
        "remediation": (
            "Add a Deny statement for cloudtrail:DeleteTrail, "
            "cloudtrail:StopLogging, and cloudtrail:UpdateTrail."
        ),
    },
    "SCP-004": {
        "title": "No Deny for leaving AWS Organizations",
        "actions": {
            "organizations:LeaveOrganization",
            "organizations:*",
        },
        "description": (
            "No SCP Deny statement prevents accounts from leaving "
            "AWS Organizations, which would remove all SCP controls."
        ),
        "remediation": (
            "Add a Deny statement for organizations:LeaveOrganization "
            "to prevent accounts from escaping organizational controls."
        ),
    },
}


def _get_actions(stmt: Dict) -> List[str]:
    """Normalize Action to a list of strings."""
    a = stmt.get("Action", [])
    if isinstance(a, str):
        return [a]
    return list(a)


def _get_resources(stmt: Dict) -> List[str]:
    r = stmt.get("Resource", [])
    if isinstance(r, str):
        return [r]
    return list(r)


def _deny_covers_action(deny_actions: List[str], target_actions: set) -> bool:
    """Return True if any deny action covers any target action."""
    deny_lower = {a.lower() for a in deny_actions}
    for ta in target_actions:
        if ta.lower() in deny_lower or "*" in deny_lower:
            return True
        # prefix wildcard: e.g. "cloudtrail:*" covers "cloudtrail:DeleteTrail"
        prefix = ta.split(":")[0].lower() + ":*"
        if prefix in deny_lower:
            return True
    return False


def _has_condition(stmt: Dict, key: str, value: str) -> bool:
    """Check if a statement has a specific condition key=value."""
    for cond_op, conditions in stmt.get("Condition", {}).items():
        if isinstance(conditions, dict):
            for k, v in conditions.items():
                if k.lower() == key.lower():
                    vals = [v] if isinstance(v, str) else list(v)
                    if any(val.lower() == value.lower() for val in vals):
                        return True
    return False


# ---------------------------------------------------------------------------
# SCPAnalyzer
# ---------------------------------------------------------------------------

class SCPAnalyzer:
    """
    Analyze a set of SCP documents for security gaps.

    Args:
        require_root_deny:       Flag SCP-002 if no root deny found (default True).
        require_cloudtrail_deny: Flag SCP-003 if no CloudTrail deny found (default True).
        require_org_deny:        Flag SCP-004 if no LeaveOrganization deny (default True).
    """

    def __init__(
        self,
        require_root_deny: bool = True,
        require_cloudtrail_deny: bool = True,
        require_org_deny: bool = True,
    ) -> None:
        self._req_root      = require_root_deny
        self._req_cloudtrail = require_cloudtrail_deny
        self._req_org        = require_org_deny

    def analyze(self, documents: List[SCPDocument]) -> SCPReport:
        """
        Analyze a list of SCP documents.

        Returns:
            SCPReport with all findings and risk score.
        """
        findings: List[SCPFinding] = []

        # SCP-006: no policies at all
        if not documents:
            findings.append(SCPFinding(
                check_id="SCP-006",
                severity=SCPSeverity.CRITICAL,
                policy_name="<none>",
                title="No SCPs attached",
                detail="No Service Control Policies are attached to this target.",
                remediation=(
                    "Attach at minimum a guardrail SCP denying root usage, "
                    "CloudTrail disablement, and Organizations leave."
                ),
            ))
            return SCPReport(
                findings=findings,
                risk_score=_CHECK_WEIGHTS["SCP-006"],
                policies_analyzed=0,
            )

        # Per-policy checks
        for doc in documents:
            findings.extend(self._check_policy(doc))

        # Cross-policy guardrail checks
        if self._req_root:
            findings.extend(self._check_guardrail("SCP-002", documents))
        if self._req_cloudtrail:
            findings.extend(self._check_guardrail("SCP-003", documents))
        if self._req_org:
            findings.extend(self._check_guardrail("SCP-004", documents))

        fired = {f.check_id for f in findings}
        score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired))

        return SCPReport(
            findings=findings,
            risk_score=score,
            policies_analyzed=len(documents),
        )

    # ------------------------------------------------------------------
    # Per-policy checks
    # ------------------------------------------------------------------

    def _check_policy(self, doc: SCPDocument) -> List[SCPFinding]:
        findings: List[SCPFinding] = []

        for stmt in doc.statements:
            effect   = stmt.get("Effect", "").upper()
            actions  = _get_actions(stmt)
            resources = _get_resources(stmt)
            not_action = stmt.get("NotAction", None)

            # SCP-001: Allow *
            if effect == "ALLOW" and ("*" in actions or "s3:*" == actions):
                if "*" in actions:
                    findings.append(SCPFinding(
                        check_id="SCP-001",
                        severity=SCPSeverity.HIGH,
                        policy_name=doc.name,
                        title="SCP allows all actions (Action: *)",
                        detail=(
                            f"Policy '{doc.name}' has an Allow statement "
                            f"with Action:* — grants unrestricted access."
                        ),
                        evidence=str(stmt)[:256],
                        remediation=(
                            "Replace Action:* with an explicit list of allowed "
                            "services/actions. Use Deny statements for guardrails."
                        ),
                    ))

            # SCP-005: Allow with Resource:*
            if effect == "ALLOW" and "*" in resources:
                findings.append(SCPFinding(
                    check_id="SCP-005",
                    severity=SCPSeverity.MEDIUM,
                    policy_name=doc.name,
                    title="SCP Allow statement applies to all resources",
                    detail=(
                        f"Policy '{doc.name}' has an Allow statement "
                        f"with Resource:* — applies to all resources."
                    ),
                    evidence=str(stmt)[:256],
                    remediation=(
                        "Scope Resource to specific ARN patterns where possible."
                    ),
                ))

            # SCP-007: NotAction
            if effect == "ALLOW" and not_action is not None:
                not_acts = [not_action] if isinstance(not_action, str) else list(not_action)
                findings.append(SCPFinding(
                    check_id="SCP-007",
                    severity=SCPSeverity.MEDIUM,
                    policy_name=doc.name,
                    title="SCP uses NotAction (implicit broad allow)",
                    detail=(
                        f"Policy '{doc.name}' has an Allow statement with "
                        f"NotAction:{not_acts} — implicitly allows everything "
                        f"except the listed actions."
                    ),
                    evidence=f"NotAction={not_acts}",
                    remediation=(
                        "Replace NotAction with an explicit Action list. "
                        "NotAction patterns are error-prone and hard to audit."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------
    # Cross-policy guardrail checks
    # ------------------------------------------------------------------

    def _check_guardrail(
        self,
        check_id: str,
        documents: List[SCPDocument],
    ) -> List[SCPFinding]:
        """Check if any SCP across all documents provides the required deny guardrail."""
        guardrail = _CRITICAL_GUARDRAILS[check_id]
        target_actions = guardrail["actions"]

        for doc in documents:
            for stmt in doc.statements:
                if stmt.get("Effect", "").upper() != "DENY":
                    continue
                deny_actions = _get_actions(stmt)
                if _deny_covers_action(deny_actions, target_actions):
                    # For root check, also verify a condition targets root
                    if check_id == "SCP-002":
                        if _has_condition(stmt, "aws:PrincipalType", "Root"):
                            return []
                        # Also accept if deny covers sts:AssumeRoot specifically
                        if any("assumeroot" in a.lower() for a in deny_actions):
                            return []
                    else:
                        return []

        # No guardrail found across all policies
        return [SCPFinding(
            check_id=check_id,
            severity=SCPSeverity.CRITICAL,
            policy_name="<all>",
            title=guardrail["title"],
            detail=guardrail["description"],
            remediation=guardrail["remediation"],
        )]
