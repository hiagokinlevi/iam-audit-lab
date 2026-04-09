# test_oauth_app_analyzer.py — Cyber Port / IAM Audit Lab
# Tests for the oauth_app_analyzer module.
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_oauth_app_analyzer.py -q

from __future__ import annotations

import sys
import os

# Allow importing from the analyzers package without an installed distribution
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import date
from typing import List, Optional

from analyzers.oauth_app_analyzer import (
    OAuthApp,
    OAuthAuthorization,
    OAUTHFinding,
    OAUTHResult,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Shared reference date — fixed to match project "today"
# ---------------------------------------------------------------------------
REF = date(2026, 4, 6)


# ---------------------------------------------------------------------------
# Factory helpers — build minimal valid objects
# ---------------------------------------------------------------------------

def _auth(user: str = "alice", role: str = "developer") -> OAuthAuthorization:
    return OAuthAuthorization(
        authorizing_user=user,
        user_role=role,
        authorized_date=date(2025, 1, 1),
    )


def _app(
    app_id: str = "app-test",
    name: str = "Test App",
    publisher: str = "Acme Corp",
    is_verified_publisher: bool = True,
    scopes: Optional[List[str]] = None,
    authorizations: Optional[List[OAuthAuthorization]] = None,
    last_used_date: Optional[date] = date(2026, 3, 1),
    token_expiry_days: Optional[int] = 30,
) -> OAuthApp:
    return OAuthApp(
        app_id=app_id,
        name=name,
        publisher=publisher,
        is_verified_publisher=is_verified_publisher,
        scopes=scopes if scopes is not None else ["read:org"],
        authorizations=authorizations if authorizations is not None else [_auth()],
        last_used_date=last_used_date,
        token_expiry_days=token_expiry_days,
    )


def _clean_app() -> OAuthApp:
    """Return an app that fires no checks at all."""
    return _app(
        scopes=["read:org"],
        authorizations=[_auth("alice", "developer")],
        last_used_date=date(2026, 3, 20),  # 17 days ago — not stale
        token_expiry_days=30,
        is_verified_publisher=True,
    )


def _get_finding(result: OAUTHResult, check_id: str) -> Optional[OAUTHFinding]:
    for f in result.findings:
        if f.check_id == check_id:
            return f
    return None


# ===========================================================================
# Sanity / helpers tests
# ===========================================================================

class TestCleanApp:
    def test_no_findings_on_clean_app(self):
        result = analyze(_clean_app(), reference_date=REF)
        assert result.findings == []

    def test_risk_score_zero_on_clean_app(self):
        result = analyze(_clean_app(), reference_date=REF)
        assert result.risk_score == 0

    def test_result_preserves_app_id(self):
        app = _app(app_id="unique-id-42")
        result = analyze(app, reference_date=REF)
        assert result.app_id == "unique-id-42"

    def test_result_preserves_app_name(self):
        app = _app(name="My Special App")
        result = analyze(app, reference_date=REF)
        assert result.app_name == "My Special App"


# ===========================================================================
# OAUTH-001 — Write / admin scopes
# ===========================================================================

class TestOAuth001:
    def test_001_fires_on_write_colon_prefix(self):
        app = _app(scopes=["write:packages"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_fires_on_admin_colon_prefix(self):
        app = _app(scopes=["admin:org"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_fires_on_delete_colon_prefix(self):
        app = _app(scopes=["delete:packages"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_fires_on_manage_infix(self):
        app = _app(scopes=["manage_runners"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_fires_on_full_access(self):
        app = _app(scopes=["full_access"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_fires_on_colon_write_suffix(self):
        app = _app(scopes=["contents:write"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_fires_on_offline_access(self):
        app = _app(scopes=["offline_access"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_does_not_fire_on_read_only_scopes(self):
        app = _app(scopes=["read:org", "read:user", "read:packages"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is None

    def test_001_does_not_fire_on_empty_scopes(self):
        app = _app(scopes=[])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is None

    def test_001_case_insensitive_match(self):
        app = _app(scopes=["WRITE:packages"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is not None

    def test_001_detail_lists_matching_scopes(self):
        app = _app(scopes=["write:packages", "delete:artifacts"])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-001")
        assert f is not None
        assert "write:packages" in f.detail
        assert "delete:artifacts" in f.detail

    def test_001_severity_is_high(self):
        app = _app(scopes=["admin:org"])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-001")
        assert f is not None
        assert f.severity == "HIGH"

    def test_001_weight_is_25(self):
        assert _CHECK_WEIGHTS["OAUTH-001"] == 25

    def test_001_risk_score_includes_weight(self):
        app = _app(scopes=["admin:org"])
        result = analyze(app, reference_date=REF)
        assert result.risk_score >= 25

    def test_001_scope_with_write_in_middle_does_not_fire_if_no_fragment(self):
        # "rewrite" does not contain ":write" or "write:" — should not fire
        app = _app(scopes=["rewrite_history"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-001") is None

    def test_001_fires_once_for_multiple_matching_scopes(self):
        app = _app(scopes=["write:packages", "admin:org", "delete:artifacts"])
        result = analyze(app, reference_date=REF)
        matching = [f for f in result.findings if f.check_id == "OAUTH-001"]
        assert len(matching) == 1


# ===========================================================================
# OAUTH-002 — Stale app (> 90 days since last use)
# ===========================================================================

class TestOAuth002:
    def test_002_fires_when_last_used_over_90_days_ago(self):
        app = _app(last_used_date=date(2026, 1, 5))  # 91 days before REF
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is not None

    def test_002_does_not_fire_when_last_used_exactly_90_days_ago(self):
        last = date(2026, 1, 6)  # exactly 90 days before 2026-04-06
        app = _app(last_used_date=last)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is None

    def test_002_does_not_fire_when_last_used_89_days_ago(self):
        last = date(2026, 1, 7)  # 89 days before REF
        app = _app(last_used_date=last)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is None

    def test_002_does_not_fire_when_last_used_is_none(self):
        app = _app(last_used_date=None)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is None

    def test_002_does_not_fire_when_used_today(self):
        app = _app(last_used_date=REF)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is None

    def test_002_detail_contains_days_since_last_use(self):
        app = _app(last_used_date=date(2025, 12, 31))  # 96 days before REF
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-002")
        assert f is not None
        assert "96" in f.detail

    def test_002_severity_is_medium(self):
        app = _app(last_used_date=date(2026, 1, 5))
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-002")
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_002_weight_is_15(self):
        assert _CHECK_WEIGHTS["OAUTH-002"] == 15

    def test_002_fires_exactly_91_days_ago(self):
        last = date(2026, 1, 4)  # 92 days before REF — should fire
        app = _app(last_used_date=last)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is not None

    def test_002_does_not_fire_when_used_yesterday(self):
        from datetime import timedelta
        app = _app(last_used_date=REF - timedelta(days=1))
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-002") is None


# ===========================================================================
# OAUTH-003 — Privileged user authorization
# ===========================================================================

class TestOAuth003:
    def test_003_fires_for_admin_role(self):
        app = _app(authorizations=[_auth("alice", "admin")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_fires_for_owner_role(self):
        app = _app(authorizations=[_auth("bob", "owner")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_fires_for_superuser_role(self):
        app = _app(authorizations=[_auth("carol", "superuser")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_fires_for_root_role(self):
        app = _app(authorizations=[_auth("dave", "root")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_fires_for_security_role(self):
        app = _app(authorizations=[_auth("eve", "security")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_fires_for_sysadmin_role(self):
        app = _app(authorizations=[_auth("frank", "sysadmin")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_does_not_fire_for_developer_role(self):
        app = _app(authorizations=[_auth("grace", "developer")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is None

    def test_003_does_not_fire_for_viewer_role(self):
        app = _app(authorizations=[_auth("henry", "viewer")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is None

    def test_003_does_not_fire_for_contributor_role(self):
        app = _app(authorizations=[_auth("irene", "contributor")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is None

    def test_003_case_insensitive_role_match(self):
        app = _app(authorizations=[_auth("julia", "ADMIN")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None

    def test_003_detail_lists_privileged_users(self):
        app = _app(authorizations=[
            _auth("alice", "admin"),
            _auth("bob", "owner"),
        ])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-003")
        assert f is not None
        assert "alice" in f.detail
        assert "bob" in f.detail

    def test_003_fires_once_even_with_multiple_privileged_users(self):
        app = _app(authorizations=[
            _auth("alice", "admin"),
            _auth("bob", "owner"),
            _auth("carol", "root"),
        ])
        result = analyze(app, reference_date=REF)
        matching = [f for f in result.findings if f.check_id == "OAUTH-003"]
        assert len(matching) == 1

    def test_003_weight_counted_once(self):
        app = _app(
            scopes=["read:org"],
            authorizations=[_auth("alice", "admin"), _auth("bob", "owner")],
            last_used_date=REF,
            token_expiry_days=30,
            is_verified_publisher=True,
        )
        result = analyze(app, reference_date=REF)
        # Only OAUTH-003 should fire; weight = 25
        assert result.risk_score == 25

    def test_003_severity_is_high(self):
        app = _app(authorizations=[_auth("alice", "admin")])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-003")
        assert f is not None
        assert f.severity == "HIGH"

    def test_003_weight_is_25(self):
        assert _CHECK_WEIGHTS["OAUTH-003"] == 25

    def test_003_mixed_roles_only_lists_privileged(self):
        app = _app(authorizations=[
            _auth("alice", "admin"),
            _auth("bob", "developer"),
        ])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-003")
        assert f is not None
        assert "alice" in f.detail
        assert "bob" not in f.detail

    def test_003_partial_match_in_role_fires(self):
        # "org_admin" contains "admin"
        app = _app(authorizations=[_auth("alice", "org_admin")])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-003") is not None


# ===========================================================================
# OAUTH-004 — Sensitive scope accumulation (>= 3)
# ===========================================================================

class TestOAuth004:
    def test_004_fires_with_exactly_3_sensitive_scopes(self):
        app = _app(scopes=["user:read", "read:email", "profile"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is not None

    def test_004_fires_with_more_than_3_sensitive_scopes(self):
        app = _app(scopes=["user:read", "read:email", "profile", "openid"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is not None

    def test_004_does_not_fire_with_exactly_2_sensitive_scopes(self):
        app = _app(scopes=["user:read", "read:email"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is None

    def test_004_does_not_fire_with_1_sensitive_scope(self):
        app = _app(scopes=["openid"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is None

    def test_004_does_not_fire_with_no_scopes(self):
        app = _app(scopes=[])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is None

    def test_004_fires_on_repo_scope(self):
        app = _app(scopes=["repo", "user", "email"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is not None

    def test_004_fires_on_security_events_scope(self):
        app = _app(scopes=["security_events", "user", "email"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is not None

    def test_004_fires_on_code_scope(self):
        app = _app(scopes=["code", "user", "email"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is not None

    def test_004_case_insensitive_keyword_match(self):
        app = _app(scopes=["USER:READ", "EMAIL", "PROFILE"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is not None

    def test_004_detail_lists_matching_scopes(self):
        app = _app(scopes=["user:read", "read:email", "profile"])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-004")
        assert f is not None
        assert "user:read" in f.detail
        assert "read:email" in f.detail
        assert "profile" in f.detail

    def test_004_severity_is_medium(self):
        app = _app(scopes=["user:read", "read:email", "profile"])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-004")
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_004_weight_is_15(self):
        assert _CHECK_WEIGHTS["OAUTH-004"] == 15

    def test_004_each_scope_counted_once_even_if_multiple_keywords_match(self):
        # "admin:email" matches both "admin" and "email" — should only count once
        app = _app(scopes=["admin:email", "user", "profile"])
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-004")
        # Three unique scopes matched -> fires
        assert f is not None
        assert f.detail.count("admin:email") == 1

    def test_004_non_sensitive_scopes_do_not_count(self):
        # "read:org", "notifications", "gist" — none contain sensitive keywords
        app = _app(scopes=["read:org", "notifications", "gist"])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-004") is None


# ===========================================================================
# OAUTH-005 — No token expiry / rotation policy
# ===========================================================================

class TestOAuth005:
    def test_005_fires_when_token_expiry_is_none(self):
        app = _app(token_expiry_days=None)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-005") is not None

    def test_005_does_not_fire_when_token_expiry_is_set(self):
        app = _app(token_expiry_days=30)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-005") is None

    def test_005_does_not_fire_when_token_expiry_is_1_day(self):
        app = _app(token_expiry_days=1)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-005") is None

    def test_005_does_not_fire_when_token_expiry_is_zero(self):
        # 0 is falsy but not None — should not fire
        app = _app(token_expiry_days=0)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-005") is None

    def test_005_severity_is_medium(self):
        app = _app(token_expiry_days=None)
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-005")
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_005_weight_is_15(self):
        assert _CHECK_WEIGHTS["OAUTH-005"] == 15

    def test_005_detail_mentions_token_expiry(self):
        app = _app(token_expiry_days=None)
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-005")
        assert f is not None
        assert "token_expiry_days" in f.detail


# ===========================================================================
# OAUTH-006 — Unverified publisher
# ===========================================================================

class TestOAuth006:
    def test_006_fires_when_not_verified(self):
        app = _app(is_verified_publisher=False)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-006") is not None

    def test_006_does_not_fire_when_verified(self):
        app = _app(is_verified_publisher=True)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-006") is None

    def test_006_does_not_fire_when_in_verified_publishers_override(self):
        app = _app(publisher="Acme Corp", is_verified_publisher=False)
        result = analyze(app, reference_date=REF, verified_publishers=["Acme Corp"])
        assert _get_finding(result, "OAUTH-006") is None

    def test_006_override_is_case_insensitive(self):
        app = _app(publisher="Acme Corp", is_verified_publisher=False)
        result = analyze(app, reference_date=REF, verified_publishers=["acme corp"])
        assert _get_finding(result, "OAUTH-006") is None

    def test_006_fires_when_publisher_not_in_override_list(self):
        app = _app(publisher="Unknown Vendor", is_verified_publisher=False)
        result = analyze(app, reference_date=REF, verified_publishers=["Acme Corp"])
        assert _get_finding(result, "OAUTH-006") is not None

    def test_006_fires_when_override_list_is_empty(self):
        app = _app(is_verified_publisher=False)
        result = analyze(app, reference_date=REF, verified_publishers=[])
        assert _get_finding(result, "OAUTH-006") is not None

    def test_006_does_not_fire_when_override_list_is_none(self):
        # No override list; but is_verified_publisher = True
        app = _app(is_verified_publisher=True)
        result = analyze(app, reference_date=REF, verified_publishers=None)
        assert _get_finding(result, "OAUTH-006") is None

    def test_006_fires_without_override_when_unverified(self):
        # No override list; is_verified_publisher = False -> fires
        app = _app(is_verified_publisher=False)
        result = analyze(app, reference_date=REF, verified_publishers=None)
        assert _get_finding(result, "OAUTH-006") is not None

    def test_006_severity_is_medium(self):
        app = _app(is_verified_publisher=False)
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-006")
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_006_weight_is_15(self):
        assert _CHECK_WEIGHTS["OAUTH-006"] == 15

    def test_006_detail_contains_publisher_name(self):
        app = _app(publisher="Shady Vendor", is_verified_publisher=False)
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-006")
        assert f is not None
        assert "Shady Vendor" in f.detail

    def test_006_verified_flag_true_overrides_absent_override_list(self):
        app = _app(publisher="NewCorp", is_verified_publisher=True)
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-006") is None


# ===========================================================================
# OAUTH-007 — Excessive blast radius (> 50 users)
# ===========================================================================

class TestOAuth007:
    def _make_auths(self, count: int) -> List[OAuthAuthorization]:
        return [_auth(user=f"user{i}", role="developer") for i in range(count)]

    def test_007_fires_when_authorizations_exceed_50(self):
        app = _app(authorizations=self._make_auths(51))
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-007") is not None

    def test_007_does_not_fire_when_authorizations_equal_50(self):
        app = _app(authorizations=self._make_auths(50))
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-007") is None

    def test_007_does_not_fire_when_authorizations_are_49(self):
        app = _app(authorizations=self._make_auths(49))
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-007") is None

    def test_007_does_not_fire_with_zero_authorizations(self):
        app = _app(authorizations=[])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-007") is None

    def test_007_does_not_fire_with_single_authorization(self):
        app = _app(authorizations=[_auth()])
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-007") is None

    def test_007_detail_contains_user_count(self):
        app = _app(authorizations=self._make_auths(75))
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-007")
        assert f is not None
        assert "75" in f.detail

    def test_007_severity_is_high(self):
        app = _app(authorizations=self._make_auths(51))
        result = analyze(app, reference_date=REF)
        f = _get_finding(result, "OAUTH-007")
        assert f is not None
        assert f.severity == "HIGH"

    def test_007_weight_is_20(self):
        assert _CHECK_WEIGHTS["OAUTH-007"] == 20

    def test_007_fires_at_100_users(self):
        app = _app(authorizations=self._make_auths(100))
        result = analyze(app, reference_date=REF)
        assert _get_finding(result, "OAUTH-007") is not None


# ===========================================================================
# Risk score tests
# ===========================================================================

class TestRiskScore:
    def test_risk_score_zero_for_clean_app(self):
        result = analyze(_clean_app(), reference_date=REF)
        assert result.risk_score == 0

    def test_risk_score_capped_at_100(self):
        # Fire as many checks as possible — total weights easily exceed 100
        auths_51 = [_auth(f"user{i}", "admin") for i in range(51)]
        app = OAuthApp(
            app_id="max-risk",
            name="Max Risk App",
            publisher="Unknown",
            is_verified_publisher=False,
            scopes=["admin:org", "write:packages", "user", "email", "profile", "openid"],
            authorizations=auths_51,
            last_used_date=date(2025, 1, 1),
            token_expiry_days=None,
        )
        result = analyze(app, reference_date=REF)
        assert result.risk_score <= 100

    def test_risk_score_equals_sum_of_unique_weights(self):
        # Only OAUTH-005 fires (token_expiry_days=None, everything else clean)
        app = _app(token_expiry_days=None, is_verified_publisher=True)
        result = analyze(app, reference_date=REF)
        fired_ids = {f.check_id for f in result.findings}
        expected = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))
        assert result.risk_score == expected

    def test_risk_score_001_plus_003(self):
        app = OAuthApp(
            app_id="combined",
            name="Combined",
            publisher="Acme",
            is_verified_publisher=True,
            scopes=["admin:org"],
            authorizations=[_auth("alice", "admin")],
            last_used_date=REF,
            token_expiry_days=30,
        )
        result = analyze(app, reference_date=REF)
        # OAUTH-001 (25) + OAUTH-003 (25) = 50
        assert result.risk_score == 50

    def test_risk_score_deduplicates_same_check_id(self):
        # Ensure check IDs cannot inflate the score by appearing twice
        app = _app(scopes=["admin:org"])
        result = analyze(app, reference_date=REF)
        check_ids = [f.check_id for f in result.findings]
        assert len(check_ids) == len(set(check_ids))

    def test_risk_score_max_without_cap(self):
        # Max possible: 001(25)+002(15)+003(25)+004(15)+005(15)+006(15)+007(20) = 130 -> capped at 100
        auths = [_auth(f"u{i}", "admin") for i in range(51)]
        app = OAuthApp(
            app_id="all-checks",
            name="All Checks",
            publisher="Unknown",
            is_verified_publisher=False,
            scopes=["admin:org", "write:packages", "user", "email", "profile", "openid"],
            authorizations=auths,
            last_used_date=date(2025, 1, 1),
            token_expiry_days=None,
        )
        result = analyze(app, reference_date=REF)
        assert result.risk_score == 100


# ===========================================================================
# OAUTHResult helper methods
# ===========================================================================

class TestOAUTHResultHelpers:
    def _result_with_checks(self) -> OAUTHResult:
        app = OAuthApp(
            app_id="helper-test",
            name="Helper Test",
            publisher="Unknown",
            is_verified_publisher=False,
            scopes=["admin:org"],
            authorizations=[_auth("alice", "admin")],
            last_used_date=REF,
            token_expiry_days=None,
        )
        return analyze(app, reference_date=REF)

    def test_to_dict_returns_dict(self):
        result = self._result_with_checks()
        d = result.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_contains_app_id(self):
        result = self._result_with_checks()
        assert result.to_dict()["app_id"] == "helper-test"

    def test_to_dict_contains_app_name(self):
        result = self._result_with_checks()
        assert result.to_dict()["app_name"] == "Helper Test"

    def test_to_dict_contains_risk_score(self):
        result = self._result_with_checks()
        d = result.to_dict()
        assert "risk_score" in d
        assert isinstance(d["risk_score"], int)

    def test_to_dict_contains_findings_list(self):
        result = self._result_with_checks()
        d = result.to_dict()
        assert "findings" in d
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_has_required_keys(self):
        result = self._result_with_checks()
        for f in result.to_dict()["findings"]:
            assert "check_id" in f
            assert "severity" in f
            assert "title" in f
            assert "detail" in f
            assert "weight" in f

    def test_summary_returns_string(self):
        result = self._result_with_checks()
        assert isinstance(result.summary(), str)

    def test_summary_contains_app_id(self):
        result = self._result_with_checks()
        assert "helper-test" in result.summary()

    def test_summary_contains_risk_score(self):
        result = self._result_with_checks()
        assert str(result.risk_score) in result.summary()

    def test_summary_contains_check_ids(self):
        result = self._result_with_checks()
        for f in result.findings:
            assert f.check_id in result.summary()

    def test_by_severity_returns_dict(self):
        result = self._result_with_checks()
        d = result.by_severity()
        assert isinstance(d, dict)

    def test_by_severity_groups_correctly(self):
        result = self._result_with_checks()
        groups = result.by_severity()
        for severity, findings in groups.items():
            for f in findings:
                assert f.severity == severity

    def test_by_severity_covers_all_findings(self):
        result = self._result_with_checks()
        total = sum(len(v) for v in result.by_severity().values())
        assert total == len(result.findings)

    def test_by_severity_empty_when_no_findings(self):
        result = analyze(_clean_app(), reference_date=REF)
        groups = result.by_severity()
        assert all(len(v) == 0 for v in groups.values()) or groups == {}


# ===========================================================================
# analyze_many
# ===========================================================================

class TestAnalyzeMany:
    def test_returns_list(self):
        results = analyze_many([_clean_app()], reference_date=REF)
        assert isinstance(results, list)

    def test_preserves_input_order(self):
        apps = [_app(app_id=f"app-{i}") for i in range(5)]
        results = analyze_many(apps, reference_date=REF)
        for i, result in enumerate(results):
            assert result.app_id == f"app-{i}"

    def test_returns_one_result_per_app(self):
        apps = [_app(app_id=f"app-{i}") for i in range(7)]
        results = analyze_many(apps, reference_date=REF)
        assert len(results) == 7

    def test_empty_list_returns_empty(self):
        results = analyze_many([], reference_date=REF)
        assert results == []

    def test_passes_reference_date_to_each(self):
        stale = _app(app_id="stale", last_used_date=date(2025, 1, 1))
        fresh = _app(app_id="fresh", last_used_date=REF)
        results = analyze_many([stale, fresh], reference_date=REF)
        stale_result = next(r for r in results if r.app_id == "stale")
        fresh_result = next(r for r in results if r.app_id == "fresh")
        assert _get_finding(stale_result, "OAUTH-002") is not None
        assert _get_finding(fresh_result, "OAUTH-002") is None

    def test_passes_verified_publishers_to_each(self):
        app = _app(publisher="Trusted Co", is_verified_publisher=False)
        results = analyze_many([app], reference_date=REF, verified_publishers=["Trusted Co"])
        assert _get_finding(results[0], "OAUTH-006") is None
