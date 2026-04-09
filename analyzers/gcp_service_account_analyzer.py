# gcp_service_account_analyzer.py
# Part of Cyber Port — IAM Audit Lab
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See https://creativecommons.org/licenses/by/4.0/ for details.
#
# Analyzes GCP service account configurations for security risks:
#   GCP-SA-001  Overly permissive project-level role (owner/editor)   CRITICAL
#   GCP-SA-002  User-managed key older than 90 days                   HIGH
#   GCP-SA-003  Default compute SA used with non-default bindings      HIGH
#   GCP-SA-004  SA bound to impersonation roles (TokenCreator/SAUser)  HIGH
#   GCP-SA-005  User-managed key never used and older than 7 days      MEDIUM
#   GCP-SA-006  More than one active user-managed key                  MEDIUM
#   GCP-SA-007  SA granted role at organization or folder level        HIGH

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check metadata
# ---------------------------------------------------------------------------

#: Mapping of check_id -> (severity, title, weight)
_CHECK_META: Dict[str, tuple] = {
    "GCP-SA-001": (
        "CRITICAL",
        "Service account has roles/owner or roles/editor at project level",
        45,
    ),
    "GCP-SA-002": (
        "HIGH",
        "User-managed service account key is older than 90 days",
        25,
    ),
    "GCP-SA-003": (
        "HIGH",
        "Default compute service account is used with non-default role bindings",
        25,
    ),
    "GCP-SA-004": (
        "HIGH",
        "Service account is bound to an impersonation role",
        25,
    ),
    "GCP-SA-005": (
        "MEDIUM",
        "User-managed key has never been used and is older than 7 days",
        15,
    ),
    "GCP-SA-006": (
        "MEDIUM",
        "Service account has more than one active user-managed key",
        15,
    ),
    "GCP-SA-007": (
        "HIGH",
        "Service account is granted a role at organization or folder level",
        20,
    ),
}

#: Weights extracted for quick lookup
_CHECK_WEIGHTS: Dict[str, int] = {cid: meta[2] for cid, meta in _CHECK_META.items()}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class GCPSAKey:
    """Represents a single GCP service account key."""

    key_id: str
    key_type: str            # "USER_MANAGED" or "SYSTEM_MANAGED"
    created_date: date
    last_used_date: Optional[date]  # None if the key has never been used


@dataclass
class GCPRoleBinding:
    """Represents a single IAM role binding for a service account."""

    role: str           # e.g. "roles/owner", "roles/storage.admin"
    resource_type: str  # "project", "organization", "folder", "bucket", etc.
    resource_id: str


@dataclass
class GCPServiceAccount:
    """Full configuration snapshot of a GCP service account."""

    email: str           # e.g. "my-sa@my-project.iam.gserviceaccount.com"
    display_name: str
    disabled: bool
    keys: List[GCPSAKey]
    role_bindings: List[GCPRoleBinding]


@dataclass
class GCPSAFinding:
    """A single security finding raised against a service account."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class GCPSAResult:
    """Aggregated analysis result for one service account."""

    sa_email: str
    findings: List[GCPSAFinding]
    risk_score: int  # min(100, sum of weights for unique fired check IDs)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "sa_email": self.sa_email,
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
        """Return a single-line human-readable summary."""
        count = len(self.findings)
        return (
            f"{self.sa_email}: {count} finding(s), risk_score={self.risk_score}"
        )

    def by_severity(self) -> Dict[str, List[GCPSAFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[GCPSAFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Roles that grant broad write/admin access at project level
_PRIVILEGED_PROJECT_ROLES = frozenset({"roles/owner", "roles/editor"})

# Roles that allow one SA to impersonate another
_IMPERSONATION_ROLES = frozenset(
    {"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"}
)

# Resource types that indicate org/folder-level scope
_ELEVATED_RESOURCE_TYPES = frozenset({"organization", "folder"})

# Suffix that identifies the default compute service account
_DEFAULT_COMPUTE_SUFFIX = "-compute@developer.gserviceaccount.com"


def _make_finding(check_id: str, detail: str) -> GCPSAFinding:
    """Construct a GCPSAFinding from the central metadata table."""
    severity, title, weight = _CHECK_META[check_id]
    return GCPSAFinding(
        check_id=check_id,
        severity=severity,
        title=title,
        detail=detail,
        weight=weight,
    )


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze(
    service_account: GCPServiceAccount,
    reference_date: Optional[date] = None,
) -> GCPSAResult:
    """Analyze a GCP service account for security risks.

    Args:
        service_account: Full configuration snapshot of the account to inspect.
        reference_date: Date used as 'today' for key age calculations.
                        Defaults to ``date.today()`` when *None*.

    Returns:
        A :class:`GCPSAResult` containing all raised findings and a composite
        risk score capped at 100.
    """
    # Disabled accounts are not active; skip all checks and return a clean result.
    if service_account.disabled:
        return GCPSAResult(
            sa_email=service_account.email,
            findings=[],
            risk_score=0,
        )

    today: date = reference_date if reference_date is not None else date.today()
    findings: List[GCPSAFinding] = []

    # Track which check IDs have fired (for weight deduplication and SA-005 suppression)
    fired_check_ids: set = set()

    # Track which key_ids already fired GCP-SA-002 (to suppress GCP-SA-005 for same key)
    sa002_key_ids: set = set()

    # ------------------------------------------------------------------
    # GCP-SA-001: owner / editor at project level
    # ------------------------------------------------------------------
    for binding in service_account.role_bindings:
        if (
            binding.role in _PRIVILEGED_PROJECT_ROLES
            and binding.resource_type == "project"
        ):
            findings.append(
                _make_finding(
                    "GCP-SA-001",
                    f"Role '{binding.role}' bound at project level "
                    f"(resource_id='{binding.resource_id}').",
                )
            )
            fired_check_ids.add("GCP-SA-001")

    # ------------------------------------------------------------------
    # GCP-SA-002: user-managed key older than 90 days
    # ------------------------------------------------------------------
    for key in service_account.keys:
        if key.key_type != "USER_MANAGED":
            continue
        age_days = (today - key.created_date).days
        if age_days > 90:
            findings.append(
                _make_finding(
                    "GCP-SA-002",
                    f"Key '{key.key_id}' is {age_days} days old "
                    f"(created {key.created_date}).",
                )
            )
            fired_check_ids.add("GCP-SA-002")
            sa002_key_ids.add(key.key_id)

    # ------------------------------------------------------------------
    # GCP-SA-003: default compute SA used with any non-default binding
    # ------------------------------------------------------------------
    if (
        service_account.email.endswith(_DEFAULT_COMPUTE_SUFFIX)
        and len(service_account.role_bindings) > 0
    ):
        binding_summary = ", ".join(
            f"'{b.role}'" for b in service_account.role_bindings
        )
        findings.append(
            _make_finding(
                "GCP-SA-003",
                f"Default compute service account has explicit role binding(s): "
                f"{binding_summary}.",
            )
        )
        fired_check_ids.add("GCP-SA-003")

    # ------------------------------------------------------------------
    # GCP-SA-004: impersonation roles (TokenCreator / SAUser)
    # ------------------------------------------------------------------
    for binding in service_account.role_bindings:
        if binding.role in _IMPERSONATION_ROLES:
            findings.append(
                _make_finding(
                    "GCP-SA-004",
                    f"Role '{binding.role}' grants impersonation capability "
                    f"(resource_id='{binding.resource_id}').",
                )
            )
            fired_check_ids.add("GCP-SA-004")

    # ------------------------------------------------------------------
    # GCP-SA-005: user-managed key never used and older than 7 days
    #             (suppressed if GCP-SA-002 already fired for the same key)
    # ------------------------------------------------------------------
    for key in service_account.keys:
        if key.key_type != "USER_MANAGED":
            continue
        if key.key_id in sa002_key_ids:
            # Already covered by the older-key check; skip to avoid double-counting
            continue
        age_days = (today - key.created_date).days
        if key.last_used_date is None and age_days > 7:
            findings.append(
                _make_finding(
                    "GCP-SA-005",
                    f"Key '{key.key_id}' has never been used and is {age_days} "
                    f"days old (created {key.created_date}).",
                )
            )
            fired_check_ids.add("GCP-SA-005")

    # ------------------------------------------------------------------
    # GCP-SA-006: more than one active user-managed key
    # ------------------------------------------------------------------
    user_managed_keys = [k for k in service_account.keys if k.key_type == "USER_MANAGED"]
    if len(user_managed_keys) > 1:
        findings.append(
            _make_finding(
                "GCP-SA-006",
                f"Service account has {len(user_managed_keys)} active "
                f"user-managed keys (key IDs: "
                f"{', '.join(k.key_id for k in user_managed_keys)}).",
            )
        )
        fired_check_ids.add("GCP-SA-006")

    # ------------------------------------------------------------------
    # GCP-SA-007: role binding at organization or folder level
    # ------------------------------------------------------------------
    for binding in service_account.role_bindings:
        if binding.resource_type in _ELEVATED_RESOURCE_TYPES:
            findings.append(
                _make_finding(
                    "GCP-SA-007",
                    f"Role '{binding.role}' is bound at {binding.resource_type} "
                    f"level (resource_id='{binding.resource_id}').",
                )
            )
            fired_check_ids.add("GCP-SA-007")

    # ------------------------------------------------------------------
    # Risk score: sum of weights for each *unique* check ID that fired
    # ------------------------------------------------------------------
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids))

    return GCPSAResult(
        sa_email=service_account.email,
        findings=findings,
        risk_score=risk_score,
    )


def analyze_many(
    service_accounts: List[GCPServiceAccount],
    reference_date: Optional[date] = None,
) -> List[GCPSAResult]:
    """Analyze a list of GCP service accounts for security risks.

    Args:
        service_accounts: Iterable of service account snapshots to inspect.
        reference_date: Passed through to :func:`analyze` for each account.

    Returns:
        A list of :class:`GCPSAResult` objects in the same order as the input.
    """
    return [analyze(sa, reference_date=reference_date) for sa in service_accounts]
