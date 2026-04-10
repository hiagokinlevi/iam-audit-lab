# iam_policy_analyzer.py
# Analyzes AWS IAM policy documents (inline or managed) for risky permission
# configurations beyond simple privilege escalation.  Covers wildcard abuse,
# sensitive-service exposure, data exfil risks, and structural issues.
#
# Checks implemented:
#   IAMP-001 — Wildcard action on sensitive service (Allow only)
#   IAMP-002 — Unrestricted s3:GetObject / s3:* → data exfil risk
#   IAMP-003 — sts:AssumeRole on Resource "*" → broad cross-account pivot
#   IAMP-004 — Deny-none pattern (≥5 Allows and 0 Denys)
#   IAMP-005 — NotAction with Effect Allow → effectively wildcard
#   IAMP-006 — NotResource with Effect Allow → grants action on everything else
#   IAMP-007 — Sensitive data action on Resource "*"
#   IAMP-008 — iam:PassRole on Resource "*" → broad privilege delegation
#
# Copyright (c) 2026 Cyber Port (github.com/hiagokinlevi)
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See: https://creativecommons.org/licenses/by/4.0/

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Services whose wildcard usage is considered critical exposure.
_SENSITIVE_SERVICES = frozenset(
    [
        "iam",
        "sts",
        "s3",
        "ec2",
        "kms",
        "secretsmanager",
        "ssm",
        "lambda",
        "cloudtrail",
        "logs",
    ]
)

# S3-specific actions that expose data exfil when the resource is unrestricted.
_S3_EXFIL_ACTIONS = frozenset(["s3:getobject", "s3:*", "*"])

# Sensitive data-plane actions that should never have resource "*".
_SENSITIVE_DATA_ACTIONS = frozenset(
    [
        "secretsmanager:getsecretvalue",
        "ssm:getparameter",
        "ssm:getparameters",
        "kms:decrypt",
        "kms:generatedatakey",
    ]
)

# Check weights used to compute risk_score.
_WEIGHTS: Dict[str, int] = {
    "IAMP-001": 45,
    "IAMP-002": 45,
    "IAMP-003": 30,
    "IAMP-004": 20,
    "IAMP-005": 30,
    "IAMP-006": 25,
    "IAMP-007": 25,
    "IAMP-008": 40,
}

# Risk tier thresholds.
_TIER_CRITICAL = 70
_TIER_HIGH = 40
_TIER_MEDIUM = 20


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class IAMPolicyDocument:
    """Input model: a single IAM policy document to analyse.

    Attributes:
        policy_id:   Unique identifier (e.g. AWS policy ID or synthetic UUID).
        policy_name: Human-readable name.
        policy_json: Raw JSON string of the IAM policy document.
        account_id:  AWS account ID (optional; used for reporting context).
        attached_to: Entity the policy is attached to, e.g. "role:MyRole".
    """

    policy_id: str
    policy_name: str
    policy_json: str                # raw JSON string of the IAM policy document
    account_id: str = ""
    attached_to: str = ""           # e.g. "role:MyRole", "user:alice", "group:Admins"


@dataclass
class IAMPCheck:
    """A single fired check result.

    Attributes:
        check_id:    Canonical identifier, e.g. "IAMP-001".
        severity:    "CRITICAL", "HIGH", or "MEDIUM".
        description: One-sentence human-readable description of the risk.
        evidence:    Concise context string quoting the offending statement.
        weight:      Numeric weight contributed to the aggregate risk_score.
    """

    check_id: str
    severity: str       # CRITICAL / HIGH / MEDIUM
    description: str
    evidence: str       # e.g. "Allow sid=ReadAll: Action=['s3:*'] Resource=['*']"
    weight: int


@dataclass
class IAMPResult:
    """Aggregated analysis result for a single IAM policy document.

    Attributes:
        policy_id:       Identifier of the analysed policy.
        policy_name:     Name of the analysed policy.
        checks_fired:    All IAMPCheck objects raised for this policy.
        risk_score:      min(100, sum of weights of all fired checks).
        risk_tier:       Categorical label derived from risk_score.
        statement_count: Number of statements found in the policy document.
    """

    policy_id: str
    policy_name: str
    checks_fired: List[IAMPCheck] = field(default_factory=list)
    risk_score: int = 0
    risk_tier: str = "LOW"
    statement_count: int = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain Python dictionary."""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "checks_fired": [
                {
                    "check_id": c.check_id,
                    "severity": c.severity,
                    "description": c.description,
                    "evidence": c.evidence,
                    "weight": c.weight,
                }
                for c in self.checks_fired
            ],
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "statement_count": self.statement_count,
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of this result."""
        count = len(self.checks_fired)
        if count == 0:
            return (
                f"Policy '{self.policy_name}': no issues detected "
                f"(risk_score={self.risk_score}, tier={self.risk_tier})."
            )
        sev_map = self.by_severity()
        parts: List[str] = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            items = sev_map.get(sev, [])
            if items:
                parts.append(f"{len(items)} {sev}")
        sev_str = ", ".join(parts)
        return (
            f"Policy '{self.policy_name}': {count} check(s) fired [{sev_str}] — "
            f"risk_score={self.risk_score}/100, tier={self.risk_tier}."
        )

    def by_severity(self) -> Dict[str, List[IAMPCheck]]:
        """Return checks_fired grouped by severity label.

        Returns a dict whose keys are the severity strings present in this
        result (never raises; returns empty dict for a clean policy).
        """
        grouped: Dict[str, List[IAMPCheck]] = {}
        for chk in self.checks_fired:
            grouped.setdefault(chk.severity, []).append(chk)
        return grouped


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalise_list(value: Any) -> List[str]:
    """Return *value* as a list of strings regardless of its original type."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _action_lower_list(actions: List[str]) -> List[str]:
    """Return all action strings lower-cased."""
    return [a.lower() for a in actions]


def _resource_lower_list(resources: List[str]) -> List[str]:
    """Return all resource strings lower-cased."""
    return [r.lower() for r in resources]


def _sid(stmt: Dict[str, Any]) -> str:
    """Extract Sid from a statement dict, returning '' when absent."""
    return str(stmt.get("Sid", ""))


def _evidence(stmt: Dict[str, Any], actions: List[str], resources: List[str]) -> str:
    """Build a concise evidence string for a finding."""
    sid_part = f"sid={_sid(stmt)}" if _sid(stmt) else "sid=(none)"
    effect = stmt.get("Effect", "?")
    return f"{effect} {sid_part}: Action={actions} Resource={resources}"


def _evidence_structural(label: str, count: int) -> str:
    """Build evidence string for structural checks (no specific statement)."""
    return label.format(count=count)


def _is_wildcard_resource(resources: List[str]) -> bool:
    """Return True when resource list is effectively unrestricted ("*")."""
    lower = _resource_lower_list(resources)
    return "*" in lower


def _is_s3_broad_resource(resources: List[str]) -> bool:
    """Return True when resource is "*" or any arn:aws:s3::: prefix pattern."""
    for r in resources:
        rl = r.lower()
        if rl == "*":
            return True
        if rl.startswith("arn:aws:s3:::"):
            return True
    return False


def _is_broad_arn_wildcard(resources: List[str]) -> bool:
    """Return True for resource "*" or an ARN that ends with wildcard."""
    for r in resources:
        rl = r.lower()
        if rl == "*":
            return True
        # e.g. arn:aws:*:*:*:* or arn:aws:secretsmanager:*:*:secret:*
        if rl.startswith("arn:aws:") and rl.endswith("*"):
            return True
    return False


def _compute_risk_tier(score: int) -> str:
    """Derive the risk tier label from a numeric score."""
    if score >= _TIER_CRITICAL:
        return "CRITICAL"
    if score >= _TIER_HIGH:
        return "HIGH"
    if score >= _TIER_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _parse_statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the Statement list from a parsed IAM policy document dict.

    Handles Statement as a list (normal) or as a single dict (valid but rare).
    """
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        # Normalise single-statement shorthand to a list.
        stmts = [stmts]
    return list(stmts)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def _check_iamp001(
    stmt: Dict[str, Any],
    actions: List[str],
    effect: str,
    checks: List[IAMPCheck],
    resources: List[str],
) -> None:
    """IAMP-001: Wildcard action on a sensitive service in an Allow statement.

    Fires when the statement Effect is Allow and any action is:
      - "*"  (global wildcard)
      - "<svc>:*" where <svc> is in the sensitive service list
    """
    if effect.lower() != "allow":
        return

    for action in actions:
        al = action.lower()
        triggered_svc: Optional[str] = None

        if al == "*":
            triggered_svc = "*"
        else:
            # Check for "<svc>:*" pattern.
            if ":" in al:
                svc, rest = al.split(":", 1)
                if rest == "*" and svc in _SENSITIVE_SERVICES:
                    triggered_svc = svc

        if triggered_svc is not None:
            checks.append(
                IAMPCheck(
                    check_id="IAMP-001",
                    severity="CRITICAL",
                    description=(
                        "Wildcard action on a sensitive service in an Allow statement "
                        "grants unrestricted access to the service API surface."
                    ),
                    evidence=_evidence(stmt, actions, resources),
                    weight=_WEIGHTS["IAMP-001"],
                )
            )
            return  # fire once per statement


def _check_iamp002(
    stmt: Dict[str, Any],
    actions: List[str],
    effect: str,
    resources: List[str],
    checks: List[IAMPCheck],
) -> None:
    """IAMP-002: Unrestricted s3:GetObject or s3:* on a broad S3 resource.

    Fires when Effect is Allow, action is one of s3:GetObject / s3:* / *,
    AND the resource is "*" or matches arn:aws:s3:::*.
    """
    if effect.lower() != "allow":
        return

    action_lower = _action_lower_list(actions)
    has_s3_action = any(a in _S3_EXFIL_ACTIONS for a in action_lower)
    if not has_s3_action:
        return

    if not _is_s3_broad_resource(resources):
        return

    checks.append(
        IAMPCheck(
            check_id="IAMP-002",
            severity="CRITICAL",
            description=(
                "Unrestricted s3:GetObject or s3:* on a broad S3 resource "
                "creates a data exfiltration risk — any object in any bucket "
                "can be read."
            ),
            evidence=_evidence(stmt, actions, resources),
            weight=_WEIGHTS["IAMP-002"],
        )
    )


def _check_iamp003(
    stmt: Dict[str, Any],
    actions: List[str],
    effect: str,
    resources: List[str],
    checks: List[IAMPCheck],
) -> None:
    """IAMP-003: sts:AssumeRole on Resource "*".

    Fires when Effect is Allow, action covers sts:AssumeRole (or sts:* / *),
    AND resource is "*".
    """
    if effect.lower() != "allow":
        return

    action_lower = _action_lower_list(actions)
    grants_assume = any(
        a == "*"
        or a == "sts:assumerole"
        or (a == "sts:*")
        for a in action_lower
    )
    if not grants_assume:
        return

    if not _is_wildcard_resource(resources):
        return

    checks.append(
        IAMPCheck(
            check_id="IAMP-003",
            severity="HIGH",
            description=(
                "sts:AssumeRole on Resource \"*\" allows assuming any role in "
                "any account — overly broad cross-account trust pivot."
            ),
            evidence=_evidence(stmt, actions, resources),
            weight=_WEIGHTS["IAMP-003"],
        )
    )


def _check_iamp005(
    stmt: Dict[str, Any],
    effect: str,
    checks: List[IAMPCheck],
) -> None:
    """IAMP-005: NotAction with Effect Allow.

    Fires when the statement uses NotAction (instead of Action) combined with
    Effect Allow — this effectively grants everything EXCEPT the listed actions.
    """
    if effect.lower() != "allow":
        return
    if "NotAction" not in stmt:
        return

    not_actions = _normalise_list(stmt.get("NotAction"))
    resources = _normalise_list(stmt.get("Resource") or stmt.get("NotResource"))
    checks.append(
        IAMPCheck(
            check_id="IAMP-005",
            severity="HIGH",
            description=(
                "NotAction with Effect Allow grants all actions EXCEPT the "
                "listed ones — effectively a wildcard grant."
            ),
            evidence=(
                f"Allow {('sid=' + _sid(stmt)) if _sid(stmt) else 'sid=(none)'}: "
                f"NotAction={not_actions} Resource={resources}"
            ),
            weight=_WEIGHTS["IAMP-005"],
        )
    )


def _check_iamp006(
    stmt: Dict[str, Any],
    effect: str,
    checks: List[IAMPCheck],
) -> None:
    """IAMP-006: NotResource with Effect Allow.

    Fires when the statement uses NotResource combined with Effect Allow —
    this grants the listed actions on every resource EXCEPT the listed ones.
    """
    if effect.lower() != "allow":
        return
    if "NotResource" not in stmt:
        return

    not_resources = _normalise_list(stmt.get("NotResource"))
    actions = _normalise_list(stmt.get("Action") or stmt.get("NotAction"))
    checks.append(
        IAMPCheck(
            check_id="IAMP-006",
            severity="HIGH",
            description=(
                "NotResource with Effect Allow grants the listed actions on "
                "all resources EXCEPT the listed ones — effectively unrestricted."
            ),
            evidence=(
                f"Allow {('sid=' + _sid(stmt)) if _sid(stmt) else 'sid=(none)'}: "
                f"Action={actions} NotResource={not_resources}"
            ),
            weight=_WEIGHTS["IAMP-006"],
        )
    )


def _check_iamp007(
    stmt: Dict[str, Any],
    actions: List[str],
    effect: str,
    resources: List[str],
    checks: List[IAMPCheck],
) -> None:
    """IAMP-007: Sensitive data action on Resource "*" or a broad ARN wildcard.

    Fires when Effect is Allow, the resource is "*" or ends with "*" starting
    from "arn:aws:", and one of the sensitive data-plane actions is covered
    (either explicitly or via a wildcard action).
    """
    if effect.lower() != "allow":
        return

    if not _is_broad_arn_wildcard(resources):
        return

    action_lower = _action_lower_list(actions)

    # An action covers a sensitive data action when it is:
    #   - The exact sensitive action itself
    #   - "*" (global wildcard)
    #   - "<svc>:*" where svc matches the sensitive action's service prefix
    def _covers_sensitive(stmt_action_lc: str, sensitive_lc: str) -> bool:
        if stmt_action_lc == sensitive_lc:
            return True
        if stmt_action_lc == "*":
            return True
        if ":" in sensitive_lc:
            svc = sensitive_lc.split(":")[0]
            if stmt_action_lc == f"{svc}:*":
                return True
        return False

    for sensitive in _SENSITIVE_DATA_ACTIONS:
        if any(_covers_sensitive(a, sensitive) for a in action_lower):
            checks.append(
                IAMPCheck(
                    check_id="IAMP-007",
                    severity="HIGH",
                    description=(
                        "Sensitive data-plane action (secret/parameter/key access) "
                        "allowed on Resource \"*\" — any secret, parameter, or key "
                        "in the account can be accessed."
                    ),
                    evidence=_evidence(stmt, actions, resources),
                    weight=_WEIGHTS["IAMP-007"],
                )
            )
            return  # fire once per statement


def _check_iamp008(
    stmt: Dict[str, Any],
    actions: List[str],
    effect: str,
    resources: List[str],
    checks: List[IAMPCheck],
) -> None:
    """IAMP-008: iam:PassRole on Resource "*".

    Fires when Effect is Allow, the action explicitly grants iam:PassRole, and
    the resource scope is unrestricted. Broader iam:* and * action grants are
    already covered by IAMP-001 to avoid double-counting the same statement.
    """
    if effect.lower() != "allow":
        return
    if not _is_wildcard_resource(resources):
        return

    action_lower = _action_lower_list(actions)
    grants_pass_role = "iam:passrole" in action_lower
    if not grants_pass_role:
        return

    checks.append(
        IAMPCheck(
            check_id="IAMP-008",
            severity="HIGH",
            description=(
                "iam:PassRole on Resource \"*\" allows passing any role to supported "
                "services, creating an indirect privilege escalation path."
            ),
            evidence=_evidence(stmt, actions, resources),
            weight=_WEIGHTS["IAMP-008"],
        )
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(policy: IAMPolicyDocument) -> IAMPResult:
    """Analyse a single IAMPolicyDocument and return an IAMPResult.

    The function is purely static — no AWS API calls are made.  If
    *policy_json* is malformed JSON the result will have an empty
    *checks_fired* list and a risk_score / risk_tier of 0 / "LOW".

    Args:
        policy: The policy document to analyse.

    Returns:
        IAMPResult with all fired checks, risk_score, and risk_tier populated.
    """
    # ------------------------------------------------------------------
    # Parse the raw JSON; return a clean empty result on failure.
    # ------------------------------------------------------------------
    try:
        doc: Dict[str, Any] = json.loads(policy.policy_json)
    except (json.JSONDecodeError, ValueError):
        return IAMPResult(
            policy_id=policy.policy_id,
            policy_name=policy.policy_name,
            checks_fired=[],
            risk_score=0,
            risk_tier="LOW",
            statement_count=0,
        )

    stmts = _parse_statements(doc)
    checks: List[IAMPCheck] = []

    # Track Allow / Deny counts for IAMP-004.
    allow_count = 0
    deny_count = 0

    for stmt in stmts:
        effect: str = stmt.get("Effect", "")
        effect_lower = effect.lower()

        if effect_lower == "allow":
            allow_count += 1
        elif effect_lower == "deny":
            deny_count += 1

        # Gather actions and resources for statement-level checks.
        # NotAction / NotResource are handled by their own checks.
        has_not_action = "NotAction" in stmt
        has_not_resource = "NotResource" in stmt

        if not has_not_action:
            actions: List[str] = _normalise_list(stmt.get("Action"))
        else:
            actions = []  # NotAction statements have no conventional actions list

        if not has_not_resource:
            resources: List[str] = _normalise_list(stmt.get("Resource"))
        else:
            resources = []  # NotResource statements — resource list is the exclusion list

        # Run statement-level checks (IAMP-001, 002, 003, 007, 008).
        if not has_not_action and not has_not_resource:
            _check_iamp001(stmt, actions, effect, checks, resources)
            _check_iamp002(stmt, actions, effect, resources, checks)
            _check_iamp003(stmt, actions, effect, resources, checks)
            _check_iamp007(stmt, actions, effect, resources, checks)
            _check_iamp008(stmt, actions, effect, resources, checks)

        # IAMP-005: NotAction + Allow
        _check_iamp005(stmt, effect, checks)

        # IAMP-006: NotResource + Allow
        _check_iamp006(stmt, effect, checks)

    # IAMP-004: policy-level structural check.
    if allow_count >= 5 and deny_count == 0:
        checks.append(
            IAMPCheck(
                check_id="IAMP-004",
                severity="MEDIUM",
                description=(
                    "The policy contains 5 or more Allow statements and zero "
                    "Deny statements — no guardrails limit the granted permissions."
                ),
                evidence=_evidence_structural(
                    "Allow count={count}, Deny count=0", allow_count
                ),
                weight=_WEIGHTS["IAMP-004"],
            )
        )

    # Deduplicate checks by check_id so that the same check never adds its
    # weight more than once to the risk_score (e.g. if multiple statements
    # each trigger IAMP-001, we still count the weight only once).
    seen_ids_for_score: Dict[str, bool] = {}
    raw_score = 0
    for chk in checks:
        if chk.check_id not in seen_ids_for_score:
            raw_score += chk.weight
            seen_ids_for_score[chk.check_id] = True

    risk_score = min(100, raw_score)
    risk_tier = _compute_risk_tier(risk_score)

    return IAMPResult(
        policy_id=policy.policy_id,
        policy_name=policy.policy_name,
        checks_fired=checks,
        risk_score=risk_score,
        risk_tier=risk_tier,
        statement_count=len(stmts),
    )


def analyze_many(policies: List[IAMPolicyDocument]) -> List[IAMPResult]:
    """Analyse a list of IAM policy documents and return one IAMPResult per policy.

    Args:
        policies: List of IAMPolicyDocument instances to analyse.

    Returns:
        List of IAMPResult, one per input policy, in the same order.
    """
    return [analyze(p) for p in policies]
