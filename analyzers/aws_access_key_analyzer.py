# aws_access_key_analyzer.py
# Part of Cyber Port — IAM Audit Lab
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See https://creativecommons.org/licenses/by/4.0/ for details.
#
# Analyzes AWS IAM access key configurations for security risks:
#   AK-001  Root account active key(s)          CRITICAL
#   AK-002  Key age > 90 days                   HIGH
#   AK-003  Key never used and older than 7 days HIGH
#   AK-004  Key last used > 90 days ago          MEDIUM
#   AK-005  Multiple active keys                 MEDIUM
#   AK-006  Console + active key + no MFA        HIGH
#   AK-007  Active key on an inactive user       HIGH

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check metadata
# ---------------------------------------------------------------------------

#: Mapping of check_id -> (severity, title, weight)
_CHECK_META: Dict[str, tuple] = {
    "AK-001": ("CRITICAL", "Root account has one or more active access keys", 45),
    "AK-002": ("HIGH",     "Access key age exceeds 90 days",                  25),
    "AK-003": ("HIGH",     "Access key was never used and is older than 7 days", 20),
    "AK-004": ("MEDIUM",   "Access key last used more than 90 days ago",       15),
    "AK-005": ("MEDIUM",   "User has multiple active access keys",             15),
    "AK-006": ("HIGH",     "Console access + active key without MFA",          25),
    "AK-007": ("HIGH",     "Active key exists for an inactive user",           20),
}

#: Convenience weight lookup used in risk_score calculation
_CHECK_WEIGHTS: Dict[str, int] = {k: v[2] for k, v in _CHECK_META.items()}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AccessKey:
    """Represents a single IAM access key (key_id shows last 4 chars only)."""

    key_id: str                       # e.g. "****WXYZ"
    status: str                       # "Active" or "Inactive"
    created_date: date
    last_used_date: Optional[date]    # None if the key was never used


@dataclass
class IAMUserKeyContext:
    """All key-related context for a single IAM user."""

    username: str
    is_root: bool           # True when username == "<root_account>"
    console_access: bool    # True if the user has a login profile
    mfa_active: bool
    user_active: bool       # False if the user account is disabled/suspended
    access_keys: List[AccessKey]


@dataclass
class AKFinding:
    """A single security finding produced by one check rule."""

    check_id: str
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str      # Human-readable detail, includes key_id where relevant
    weight: int


@dataclass
class AKResult:
    """Aggregated analysis result for one IAM user."""

    username: str
    findings: List[AKFinding] = field(default_factory=list)
    risk_score: int = 0

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the result to a plain dictionary (JSON-safe)."""
        return {
            "username": self.username,
            "risk_score": self.risk_score,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line summary string."""
        n = len(self.findings)
        severities = [f.severity for f in self.findings]
        counts: Dict[str, int] = {}
        for s in severities:
            counts[s] = counts.get(s, 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(counts.items())]
        breakdown = ", ".join(parts) if parts else "none"
        return (
            f"User '{self.username}': risk_score={self.risk_score}, "
            f"findings={n} ({breakdown})"
        )

    def by_severity(self) -> Dict[str, List[AKFinding]]:
        """Group findings by severity level."""
        grouped: Dict[str, List[AKFinding]] = {}
        for f in self.findings:
            grouped.setdefault(f.severity, []).append(f)
        return grouped


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_finding(check_id: str, detail: str) -> AKFinding:
    """Construct an AKFinding from the central metadata table."""
    severity, title, weight = _CHECK_META[check_id]
    return AKFinding(
        check_id=check_id,
        severity=severity,
        title=title,
        detail=detail,
        weight=weight,
    )


def _active_keys(user: IAMUserKeyContext) -> List[AccessKey]:
    """Return only the Active keys for a user."""
    return [k for k in user.access_keys if k.status == "Active"]


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------

def analyze(
    user: IAMUserKeyContext,
    reference_date: Optional[date] = None,
) -> AKResult:
    """Analyze a user's access keys for security risks.

    Args:
        user: Full key context for the IAM user.
        reference_date: Treated as 'today' for age calculations.
            Defaults to ``date.today()`` when not supplied.

    Returns:
        An :class:`AKResult` with all fired findings and a capped risk score.
    """
    if reference_date is None:
        reference_date = date.today()

    findings: List[AKFinding] = []
    active = _active_keys(user)

    # ------------------------------------------------------------------
    # AK-001: Root account has one or more active access keys
    # ------------------------------------------------------------------
    if user.is_root and active:
        findings.append(
            _make_finding(
                "AK-001",
                f"Root account '{user.username}' has {len(active)} active "
                f"access key(s). Root keys pose extreme security risk.",
            )
        )

    # ------------------------------------------------------------------
    # AK-002: Key age > 90 days  (one finding per affected active key)
    # AK-003: Never used, older than 7 days (one finding per affected key)
    # AK-004: Last used > 90 days ago (per key; skipped if AK-003 fires)
    # AK-007: Active key on an inactive user (one finding per active key)
    # ------------------------------------------------------------------
    for key in active:
        age_days = (reference_date - key.created_date).days

        # AK-002 — stale by creation date
        if age_days > 90:
            findings.append(
                _make_finding(
                    "AK-002",
                    f"Key {key.key_id} is {age_days} days old (created "
                    f"{key.created_date}). Rotation threshold is 90 days.",
                )
            )

        # AK-003 — never used and older than 7 days
        never_used_fired = False
        if key.last_used_date is None and age_days > 7:
            never_used_fired = True
            findings.append(
                _make_finding(
                    "AK-003",
                    f"Key {key.key_id} has never been used and was created "
                    f"{age_days} days ago (created {key.created_date}).",
                )
            )

        # AK-004 — last used > 90 days ago; skip if AK-003 already fired
        if not never_used_fired and key.last_used_date is not None:
            days_since_use = (reference_date - key.last_used_date).days
            if days_since_use > 90:
                findings.append(
                    _make_finding(
                        "AK-004",
                        f"Key {key.key_id} was last used {days_since_use} days ago "
                        f"(last used {key.last_used_date}). Threshold is 90 days.",
                    )
                )

        # AK-007 — active key for a disabled user
        if not user.user_active:
            findings.append(
                _make_finding(
                    "AK-007",
                    f"Key {key.key_id} is Active but user '{user.username}' "
                    f"is marked as inactive.",
                )
            )

    # ------------------------------------------------------------------
    # AK-005: More than one active key
    # ------------------------------------------------------------------
    if len(active) > 1:
        findings.append(
            _make_finding(
                "AK-005",
                f"User '{user.username}' has {len(active)} active access keys "
                f"({', '.join(k.key_id for k in active)}). "
                f"At most one active key is recommended.",
            )
        )

    # ------------------------------------------------------------------
    # AK-006: Console login + active key + no MFA
    # ------------------------------------------------------------------
    if user.console_access and not user.mfa_active and active:
        key_ids = ", ".join(k.key_id for k in active)
        findings.append(
            _make_finding(
                "AK-006",
                f"User '{user.username}' has console access without MFA and "
                f"also holds active key(s): {key_ids}.",
            )
        )

    # ------------------------------------------------------------------
    # Risk score: sum unique check IDs, cap at 100
    # ------------------------------------------------------------------
    fired_ids = {f.check_id for f in findings}
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

    return AKResult(username=user.username, findings=findings, risk_score=risk_score)


# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------

def analyze_many(
    users: List[IAMUserKeyContext],
    reference_date: Optional[date] = None,
) -> List[AKResult]:
    """Run :func:`analyze` over a list of users and return all results.

    Args:
        users: List of :class:`IAMUserKeyContext` objects.
        reference_date: Forwarded unchanged to :func:`analyze`.

    Returns:
        A list of :class:`AKResult` objects, one per user, in input order.
    """
    return [analyze(u, reference_date=reference_date) for u in users]
