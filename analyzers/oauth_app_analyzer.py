# oauth_app_analyzer.py — Cyber Port / IAM Audit Lab
# Analyze OAuth application authorization configurations for security risks.
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Author: Cyber Port — github.com/hiagokinlevi
# Compatible with Python 3.9+

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weight registry
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "OAUTH-001": 25,  # Write / admin scopes requested
    "OAUTH-002": 15,  # App not used in more than 90 days
    "OAUTH-003": 25,  # Privileged user authorization
    "OAUTH-004": 15,  # Sensitive scope accumulation (>= 3 sensitive scopes)
    "OAUTH-005": 15,  # No token expiry / rotation policy
    "OAUTH-006": 15,  # Unverified publisher
    "OAUTH-007": 20,  # Excessive blast radius (> 50 authorizations)
}

# Scope fragments that indicate write / admin access (OAUTH-001)
_WRITE_ADMIN_FRAGMENTS: List[str] = [
    "write:",        # GitHub-style prefix  e.g. write:packages
    "admin:",        # prefix               e.g. admin:org
    "delete:",       # prefix               e.g. delete:packages
    "manage_",       # infix                e.g. manage_runners
    "full_access",   # literal              e.g. full_access
    ":write",        # suffix               e.g. contents:write
    "offline_access",# literal              e.g. offline_access (long-lived tokens)
]

# Sensitive scope keywords used for scope-accumulation check (OAUTH-004)
_SENSITIVE_SCOPE_KEYWORDS: List[str] = [
    "user",
    "email",
    "profile",
    "openid",
    "repo",
    "code",
    "admin",
    "security_events",
]

# Role substrings that indicate a privileged account (OAUTH-003)
_PRIVILEGED_ROLE_FRAGMENTS: List[str] = [
    "admin",
    "owner",
    "superuser",
    "root",
    "security",
    "sysadmin",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class OAuthAuthorization:
    """Represents a single user's authorization of an OAuth application."""

    authorizing_user: str   # username or user ID
    user_role: str          # e.g. "admin", "developer", "viewer"
    authorized_date: date


@dataclass
class OAuthApp:
    """Full description of an OAuth application and its authorization state."""

    app_id: str
    name: str
    publisher: str
    is_verified_publisher: bool
    scopes: List[str]                    # list of OAuth scope strings
    authorizations: List[OAuthAuthorization]
    last_used_date: Optional[date]
    token_expiry_days: Optional[int]


@dataclass
class OAUTHFinding:
    """A single security finding for an OAuth application."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class OAUTHResult:
    """Aggregated analysis result for one OAuth application."""

    app_id: str
    app_name: str
    findings: List[OAUTHFinding]
    risk_score: int  # min(100, sum of weights for unique fired check IDs)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the result to a plain dictionary (JSON-friendly)."""
        return {
            "app_id": self.app_id,
            "app_name": self.app_name,
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
        checks = ", ".join(sorted(f.check_id for f in self.findings)) if self.findings else "none"
        return (
            f"[{self.app_id}] {self.app_name} — "
            f"risk_score={self.risk_score}/100, "
            f"findings={count} ({checks})"
        )

    def by_severity(self) -> Dict[str, List[OAUTHFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[OAUTHFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal check helpers
# ---------------------------------------------------------------------------

def _check_001(app: OAuthApp) -> Optional[OAUTHFinding]:
    """OAUTH-001 — App requests write / admin scopes on sensitive resources."""
    matched: List[str] = []
    for scope in app.scopes:
        scope_lower = scope.lower()
        for fragment in _WRITE_ADMIN_FRAGMENTS:
            if fragment in scope_lower:
                matched.append(scope)
                break  # avoid duplicating the same scope for multiple fragments
    if not matched:
        return None
    return OAUTHFinding(
        check_id="OAUTH-001",
        severity="HIGH",
        title="App requests write/admin scopes on sensitive resources",
        detail=(
            f"The following write or admin scopes were found: "
            f"{', '.join(matched)}"
        ),
        weight=_CHECK_WEIGHTS["OAUTH-001"],
    )


def _check_002(app: OAuthApp, reference_date: date) -> Optional[OAUTHFinding]:
    """OAUTH-002 — App has not been used in more than 90 days."""
    if app.last_used_date is None:
        # Unknown last-use; cannot determine staleness — skip
        return None
    days_since = (reference_date - app.last_used_date).days
    if days_since <= 90:
        return None
    return OAUTHFinding(
        check_id="OAUTH-002",
        severity="MEDIUM",
        title="App has not been used in more than 90 days",
        detail=(
            f"Last activity was {days_since} day(s) ago "
            f"(last_used_date={app.last_used_date.isoformat()})."
        ),
        weight=_CHECK_WEIGHTS["OAUTH-002"],
    )


def _check_003(app: OAuthApp) -> Optional[OAUTHFinding]:
    """OAUTH-003 — App is authorized by a user with a privileged role."""
    privileged_users: List[str] = []
    for auth in app.authorizations:
        role_lower = auth.user_role.lower()
        for fragment in _PRIVILEGED_ROLE_FRAGMENTS:
            if fragment in role_lower:
                privileged_users.append(
                    f"{auth.authorizing_user} (role={auth.user_role})"
                )
                break  # avoid counting the same user multiple times
    if not privileged_users:
        return None
    return OAUTHFinding(
        check_id="OAUTH-003",
        severity="HIGH",
        title="App is authorized by a user with a privileged role",
        detail=(
            f"Privileged authorizing user(s): "
            f"{', '.join(privileged_users)}"
        ),
        weight=_CHECK_WEIGHTS["OAUTH-003"],
    )


def _check_004(app: OAuthApp) -> Optional[OAUTHFinding]:
    """OAUTH-004 — App requests sensitive OAuth scopes (accumulation >= 3)."""
    matched: List[str] = []
    for scope in app.scopes:
        scope_lower = scope.lower()
        for keyword in _SENSITIVE_SCOPE_KEYWORDS:
            if keyword in scope_lower:
                matched.append(scope)
                break  # avoid counting the same scope twice
    if len(matched) < 3:
        return None
    return OAUTHFinding(
        check_id="OAUTH-004",
        severity="MEDIUM",
        title="App requests an accumulation of sensitive OAuth scopes",
        detail=(
            f"{len(matched)} sensitive scope(s) detected: "
            f"{', '.join(matched)}"
        ),
        weight=_CHECK_WEIGHTS["OAUTH-004"],
    )


def _check_005(app: OAuthApp) -> Optional[OAUTHFinding]:
    """OAUTH-005 — No token expiry or rotation policy configured."""
    if app.token_expiry_days is not None:
        return None
    return OAUTHFinding(
        check_id="OAUTH-005",
        severity="MEDIUM",
        title="No token expiry or rotation policy configured",
        detail=(
            "token_expiry_days is not set. Tokens may be valid indefinitely, "
            "increasing the window of exposure for compromised credentials."
        ),
        weight=_CHECK_WEIGHTS["OAUTH-005"],
    )


def _check_006(
    app: OAuthApp,
    verified_publishers: Optional[List[str]],
) -> Optional[OAUTHFinding]:
    """OAUTH-006 — App publisher is not in the verified publishers list."""
    # If the caller supplied an override list, check it first
    if verified_publishers is not None:
        lowered = [p.lower() for p in verified_publishers]
        if app.publisher.lower() in lowered:
            return None  # trusted via caller-supplied list
    if app.is_verified_publisher:
        return None
    return OAUTHFinding(
        check_id="OAUTH-006",
        severity="MEDIUM",
        title="App publisher is not verified",
        detail=(
            f"Publisher '{app.publisher}' is not marked as verified and is "
            "not present in the verified_publishers override list."
        ),
        weight=_CHECK_WEIGHTS["OAUTH-006"],
    )


def _check_007(app: OAuthApp) -> Optional[OAUTHFinding]:
    """OAUTH-007 — App is authorized by more than 50 users (blast radius)."""
    count = len(app.authorizations)
    if count <= 50:
        return None
    return OAUTHFinding(
        check_id="OAUTH-007",
        severity="HIGH",
        title="App has a widespread blast radius",
        detail=(
            f"The app is authorized by {count} user(s), which exceeds the "
            "threshold of 50. A compromise would affect a large number of accounts."
        ),
        weight=_CHECK_WEIGHTS["OAUTH-007"],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    app: OAuthApp,
    reference_date: Optional[date] = None,
    verified_publishers: Optional[List[str]] = None,
) -> OAUTHResult:
    """Analyze an OAuth app authorization for security risks.

    Parameters
    ----------
    app:
        The OAuth application to evaluate.
    reference_date:
        Used as 'today' for staleness calculations. Defaults to date.today().
    verified_publishers:
        Optional list of trusted publisher names (case-insensitive). When a
        publisher appears in this list, OAUTH-006 will not fire even if
        ``is_verified_publisher`` is False.

    Returns
    -------
    OAUTHResult
        Aggregated findings and risk score for the supplied app.
    """
    if reference_date is None:
        reference_date = date.today()

    findings: List[OAUTHFinding] = []

    # Run each check and collect non-None findings
    for check_fn in (
        lambda: _check_001(app),
        lambda: _check_002(app, reference_date),
        lambda: _check_003(app),
        lambda: _check_004(app),
        lambda: _check_005(app),
        lambda: _check_006(app, verified_publishers),
        lambda: _check_007(app),
    ):
        result = check_fn()
        if result is not None:
            findings.append(result)

    # Deduplicate by check_id (defensive — each check fires at most once)
    seen_ids: set = set()
    unique_findings: List[OAUTHFinding] = []
    for f in findings:
        if f.check_id not in seen_ids:
            seen_ids.add(f.check_id)
            unique_findings.append(f)

    risk_score = min(100, sum(_CHECK_WEIGHTS[f.check_id] for f in unique_findings))

    return OAUTHResult(
        app_id=app.app_id,
        app_name=app.name,
        findings=unique_findings,
        risk_score=risk_score,
    )


def analyze_many(
    apps: List[OAuthApp],
    reference_date: Optional[date] = None,
    verified_publishers: Optional[List[str]] = None,
) -> List[OAUTHResult]:
    """Analyze a collection of OAuth applications.

    Parameters
    ----------
    apps:
        Sequence of OAuth applications to evaluate.
    reference_date:
        Passed through to each ``analyze()`` call.
    verified_publishers:
        Passed through to each ``analyze()`` call.

    Returns
    -------
    List[OAUTHResult]
        One result per app, preserving input order.
    """
    return [
        analyze(app, reference_date=reference_date, verified_publishers=verified_publishers)
        for app in apps
    ]
