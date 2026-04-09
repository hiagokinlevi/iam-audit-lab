# test_gcp_service_account_analyzer.py
# Part of Cyber Port — IAM Audit Lab
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See https://creativecommons.org/licenses/by/4.0/ for details.
#
# Unit tests for gcp_service_account_analyzer.py
# Run with: python -m pytest tests/test_gcp_service_account_analyzer.py -q

import sys
import os

# Ensure the analyzers package is importable when running from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import date
from typing import List

from analyzers.gcp_service_account_analyzer import (
    GCPRoleBinding,
    GCPSAFinding,
    GCPSAKey,
    GCPSAResult,
    GCPServiceAccount,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Shared reference date (fixed so tests are deterministic)
# ---------------------------------------------------------------------------

REF = date(2026, 4, 6)  # "today" for all age-based calculations

# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _sa(
    email: str = "svc@my-project.iam.gserviceaccount.com",
    display_name: str = "Test SA",
    disabled: bool = False,
    keys: List[GCPSAKey] = None,
    role_bindings: List[GCPRoleBinding] = None,
) -> GCPServiceAccount:
    return GCPServiceAccount(
        email=email,
        display_name=display_name,
        disabled=disabled,
        keys=keys or [],
        role_bindings=role_bindings or [],
    )


def _user_key(
    key_id: str = "key-1",
    created_days_ago: int = 0,
    last_used_days_ago: int = None,  # None means never used
) -> GCPSAKey:
    created = date.fromordinal(REF.toordinal() - created_days_ago)
    last_used = (
        date.fromordinal(REF.toordinal() - last_used_days_ago)
        if last_used_days_ago is not None
        else None
    )
    return GCPSAKey(
        key_id=key_id,
        key_type="USER_MANAGED",
        created_date=created,
        last_used_date=last_used,
    )


def _sys_key(key_id: str = "sys-1", created_days_ago: int = 200) -> GCPSAKey:
    created = date.fromordinal(REF.toordinal() - created_days_ago)
    return GCPSAKey(
        key_id=key_id,
        key_type="SYSTEM_MANAGED",
        created_date=created,
        last_used_date=None,
    )


def _binding(
    role: str = "roles/viewer",
    resource_type: str = "project",
    resource_id: str = "my-project",
) -> GCPRoleBinding:
    return GCPRoleBinding(role=role, resource_type=resource_type, resource_id=resource_id)


def _check_ids(result: GCPSAResult) -> List[str]:
    return [f.check_id for f in result.findings]


def _unique_check_ids(result: GCPSAResult) -> set:
    return {f.check_id for f in result.findings}


# ---------------------------------------------------------------------------
# Disabled SA — all checks must be skipped
# ---------------------------------------------------------------------------


def test_disabled_sa_returns_no_findings():
    sa = _sa(
        disabled=True,
        keys=[_user_key("k1", created_days_ago=200)],
        role_bindings=[_binding("roles/owner", "project", "p1")],
    )
    result = analyze(sa, REF)
    assert result.findings == []


def test_disabled_sa_risk_score_is_zero():
    sa = _sa(disabled=True, role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    assert result.risk_score == 0


def test_disabled_sa_email_preserved():
    sa = _sa(email="disabled@proj.iam.gserviceaccount.com", disabled=True)
    result = analyze(sa, REF)
    assert result.sa_email == "disabled@proj.iam.gserviceaccount.com"


def test_disabled_sa_with_many_bad_keys_still_clean():
    keys = [_user_key(f"k{i}", created_days_ago=200) for i in range(5)]
    sa = _sa(disabled=True, keys=keys)
    result = analyze(sa, REF)
    assert result.findings == []
    assert result.risk_score == 0


# ---------------------------------------------------------------------------
# GCP-SA-001: owner / editor at project level
# ---------------------------------------------------------------------------


def test_sa001_fires_for_roles_owner():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" in _check_ids(result)


def test_sa001_fires_for_roles_editor():
    sa = _sa(role_bindings=[_binding("roles/editor", "project", "p1")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" in _check_ids(result)


def test_sa001_does_not_fire_for_viewer():
    sa = _sa(role_bindings=[_binding("roles/viewer", "project", "p1")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" not in _check_ids(result)


def test_sa001_does_not_fire_for_storage_admin():
    sa = _sa(role_bindings=[_binding("roles/storage.admin", "project", "p1")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" not in _check_ids(result)


def test_sa001_does_not_fire_for_owner_at_org_level():
    # owner at org level triggers SA-007, NOT SA-001
    sa = _sa(role_bindings=[_binding("roles/owner", "organization", "org-123")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" not in _check_ids(result)


def test_sa001_does_not_fire_for_owner_at_folder_level():
    sa = _sa(role_bindings=[_binding("roles/owner", "folder", "folder-99")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" not in _check_ids(result)


def test_sa001_multiple_bindings_produce_multiple_findings():
    bindings = [
        _binding("roles/owner", "project", "p1"),
        _binding("roles/editor", "project", "p2"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    sa001_findings = [f for f in result.findings if f.check_id == "GCP-SA-001"]
    assert len(sa001_findings) == 2


def test_sa001_severity_is_critical():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-001")
    assert f.severity == "CRITICAL"


def test_sa001_weight_is_45():
    assert _CHECK_WEIGHTS["GCP-SA-001"] == 45


def test_sa001_weight_contributes_once_to_risk_score():
    # Two owner bindings: weight 45 counted only once
    bindings = [
        _binding("roles/owner", "project", "p1"),
        _binding("roles/owner", "project", "p2"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    assert result.risk_score == 45


def test_sa001_detail_contains_role():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "my-proj")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-001")
    assert "roles/owner" in f.detail


def test_sa001_detail_contains_resource_id():
    sa = _sa(role_bindings=[_binding("roles/editor", "project", "target-proj")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-001")
    assert "target-proj" in f.detail


# ---------------------------------------------------------------------------
# GCP-SA-002: user-managed key older than 90 days
# ---------------------------------------------------------------------------


def test_sa002_fires_for_key_91_days_old():
    sa = _sa(keys=[_user_key("k1", created_days_ago=91)])
    result = analyze(sa, REF)
    assert "GCP-SA-002" in _check_ids(result)


def test_sa002_does_not_fire_for_key_exactly_90_days_old():
    sa = _sa(keys=[_user_key("k1", created_days_ago=90)])
    result = analyze(sa, REF)
    assert "GCP-SA-002" not in _check_ids(result)


def test_sa002_does_not_fire_for_key_89_days_old():
    sa = _sa(keys=[_user_key("k1", created_days_ago=89)])
    result = analyze(sa, REF)
    assert "GCP-SA-002" not in _check_ids(result)


def test_sa002_does_not_fire_for_system_managed_key():
    sa = _sa(keys=[_sys_key("sk1", created_days_ago=200)])
    result = analyze(sa, REF)
    assert "GCP-SA-002" not in _check_ids(result)


def test_sa002_multiple_old_keys_produce_multiple_findings():
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=100),
        _user_key("k2", created_days_ago=120),
    ])
    result = analyze(sa, REF)
    sa002_findings = [f for f in result.findings if f.check_id == "GCP-SA-002"]
    assert len(sa002_findings) == 2


def test_sa002_severity_is_high():
    sa = _sa(keys=[_user_key("k1", created_days_ago=91)])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-002")
    assert f.severity == "HIGH"


def test_sa002_weight_is_25():
    assert _CHECK_WEIGHTS["GCP-SA-002"] == 25


def test_sa002_weight_counted_once_for_two_old_keys():
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=100),
        _user_key("k2", created_days_ago=150),
    ])
    result = analyze(sa, REF)
    # Only SA-002 fires → weight = 25 (plus SA-006 since >1 key = 25+15=40)
    assert result.risk_score == 25 + 15  # SA-002 + SA-006


def test_sa002_detail_contains_key_id():
    sa = _sa(keys=[_user_key("unique-key-xyz", created_days_ago=95)])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-002")
    assert "unique-key-xyz" in f.detail


def test_sa002_detail_contains_age():
    sa = _sa(keys=[_user_key("k1", created_days_ago=95)])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-002")
    assert "95" in f.detail


# ---------------------------------------------------------------------------
# GCP-SA-003: default compute SA used with any non-default binding
# ---------------------------------------------------------------------------

_COMPUTE_EMAIL = "123456789-compute@developer.gserviceaccount.com"
_REGULAR_EMAIL = "svc@my-proj.iam.gserviceaccount.com"


def test_sa003_fires_for_default_compute_with_binding():
    sa = _sa(
        email=_COMPUTE_EMAIL,
        role_bindings=[_binding("roles/storage.objectViewer", "project", "p1")],
    )
    result = analyze(sa, REF)
    assert "GCP-SA-003" in _check_ids(result)


def test_sa003_does_not_fire_for_default_compute_without_bindings():
    sa = _sa(email=_COMPUTE_EMAIL, role_bindings=[])
    result = analyze(sa, REF)
    assert "GCP-SA-003" not in _check_ids(result)


def test_sa003_does_not_fire_for_non_compute_sa_with_binding():
    sa = _sa(email=_REGULAR_EMAIL, role_bindings=[_binding("roles/storage.admin")])
    result = analyze(sa, REF)
    assert "GCP-SA-003" not in _check_ids(result)


def test_sa003_only_one_finding_even_with_multiple_bindings():
    bindings = [
        _binding("roles/storage.admin", "project", "p1"),
        _binding("roles/bigquery.admin", "project", "p1"),
    ]
    sa = _sa(email=_COMPUTE_EMAIL, role_bindings=bindings)
    result = analyze(sa, REF)
    sa003_findings = [f for f in result.findings if f.check_id == "GCP-SA-003"]
    assert len(sa003_findings) == 1


def test_sa003_severity_is_high():
    sa = _sa(email=_COMPUTE_EMAIL, role_bindings=[_binding("roles/editor")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-003")
    assert f.severity == "HIGH"


def test_sa003_weight_is_25():
    assert _CHECK_WEIGHTS["GCP-SA-003"] == 25


def test_sa003_email_suffix_check_is_exact():
    # A SA that happens to contain "compute" but does not end with the suffix
    sa = _sa(
        email="compute-worker@my-proj.iam.gserviceaccount.com",
        role_bindings=[_binding("roles/viewer")],
    )
    result = analyze(sa, REF)
    assert "GCP-SA-003" not in _check_ids(result)


def test_sa003_detail_mentions_binding():
    sa = _sa(
        email=_COMPUTE_EMAIL,
        role_bindings=[_binding("roles/pubsub.publisher", "project", "proj1")],
    )
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-003")
    assert "roles/pubsub.publisher" in f.detail


# ---------------------------------------------------------------------------
# GCP-SA-004: impersonation roles (TokenCreator / SAUser)
# ---------------------------------------------------------------------------


def test_sa004_fires_for_token_creator():
    sa = _sa(role_bindings=[
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1")
    ])
    result = analyze(sa, REF)
    assert "GCP-SA-004" in _check_ids(result)


def test_sa004_fires_for_service_account_user():
    sa = _sa(role_bindings=[
        _binding("roles/iam.serviceAccountUser", "project", "p1")
    ])
    result = analyze(sa, REF)
    assert "GCP-SA-004" in _check_ids(result)


def test_sa004_does_not_fire_for_iam_viewer():
    sa = _sa(role_bindings=[_binding("roles/iam.securityReviewer", "project", "p1")])
    result = analyze(sa, REF)
    assert "GCP-SA-004" not in _check_ids(result)


def test_sa004_multiple_impersonation_bindings_produce_multiple_findings():
    bindings = [
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1"),
        _binding("roles/iam.serviceAccountUser", "project", "p1"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    sa004_findings = [f for f in result.findings if f.check_id == "GCP-SA-004"]
    assert len(sa004_findings) == 2


def test_sa004_severity_is_high():
    sa = _sa(role_bindings=[
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1")
    ])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-004")
    assert f.severity == "HIGH"


def test_sa004_weight_is_25():
    assert _CHECK_WEIGHTS["GCP-SA-004"] == 25


def test_sa004_weight_counted_once_for_two_impersonation_bindings():
    bindings = [
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1"),
        _binding("roles/iam.serviceAccountUser", "project", "p2"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    assert result.risk_score == 25  # one unique check ID


def test_sa004_detail_contains_role():
    sa = _sa(role_bindings=[
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1")
    ])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-004")
    assert "roles/iam.serviceAccountTokenCreator" in f.detail


def test_sa004_detail_contains_resource_id():
    sa = _sa(role_bindings=[
        _binding("roles/iam.serviceAccountUser", "project", "resource-xyz")
    ])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-004")
    assert "resource-xyz" in f.detail


# ---------------------------------------------------------------------------
# GCP-SA-005: user-managed key never used and older than 7 days
# ---------------------------------------------------------------------------


def test_sa005_fires_for_key_8_days_old_never_used():
    sa = _sa(keys=[_user_key("k1", created_days_ago=8, last_used_days_ago=None)])
    result = analyze(sa, REF)
    assert "GCP-SA-005" in _check_ids(result)


def test_sa005_does_not_fire_for_key_7_days_old():
    sa = _sa(keys=[_user_key("k1", created_days_ago=7, last_used_days_ago=None)])
    result = analyze(sa, REF)
    assert "GCP-SA-005" not in _check_ids(result)


def test_sa005_does_not_fire_for_key_3_days_old():
    sa = _sa(keys=[_user_key("k1", created_days_ago=3, last_used_days_ago=None)])
    result = analyze(sa, REF)
    assert "GCP-SA-005" not in _check_ids(result)


def test_sa005_does_not_fire_when_key_has_been_used():
    # Key is 30 days old but was used 10 days ago
    sa = _sa(keys=[_user_key("k1", created_days_ago=30, last_used_days_ago=10)])
    result = analyze(sa, REF)
    assert "GCP-SA-005" not in _check_ids(result)


def test_sa005_suppressed_when_sa002_fires_for_same_key():
    # Key is 91 days old and never used — SA-002 fires, SA-005 must be suppressed
    sa = _sa(keys=[_user_key("k1", created_days_ago=91, last_used_days_ago=None)])
    result = analyze(sa, REF)
    assert "GCP-SA-002" in _check_ids(result)
    assert "GCP-SA-005" not in _check_ids(result)


def test_sa005_fires_when_sa002_fires_for_different_key():
    # k1 triggers SA-002 (91 days old); k2 triggers SA-005 (10 days old, never used)
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=91, last_used_days_ago=5),
        _user_key("k2", created_days_ago=10, last_used_days_ago=None),
    ])
    result = analyze(sa, REF)
    assert "GCP-SA-002" in _check_ids(result)
    assert "GCP-SA-005" in _check_ids(result)


def test_sa005_does_not_fire_for_system_managed_key():
    sa = _sa(keys=[_sys_key("sk1", created_days_ago=200)])
    result = analyze(sa, REF)
    assert "GCP-SA-005" not in _check_ids(result)


def test_sa005_severity_is_medium():
    sa = _sa(keys=[_user_key("k1", created_days_ago=10, last_used_days_ago=None)])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-005")
    assert f.severity == "MEDIUM"


def test_sa005_weight_is_15():
    assert _CHECK_WEIGHTS["GCP-SA-005"] == 15


def test_sa005_multiple_never_used_keys_produce_multiple_findings():
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=10, last_used_days_ago=None),
        _user_key("k2", created_days_ago=15, last_used_days_ago=None),
    ])
    result = analyze(sa, REF)
    sa005_findings = [f for f in result.findings if f.check_id == "GCP-SA-005"]
    # Both keys also trigger SA-006 (>1 user-managed key)
    assert len(sa005_findings) == 2


def test_sa005_weight_counted_once_even_with_two_affected_keys():
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=10, last_used_days_ago=None),
        _user_key("k2", created_days_ago=12, last_used_days_ago=None),
    ])
    result = analyze(sa, REF)
    # SA-005 (15) + SA-006 (15) = 30
    assert result.risk_score == 15 + 15


def test_sa005_detail_contains_key_id():
    sa = _sa(keys=[_user_key("stale-key-abc", created_days_ago=20, last_used_days_ago=None)])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-005")
    assert "stale-key-abc" in f.detail


# ---------------------------------------------------------------------------
# GCP-SA-006: more than one active user-managed key
# ---------------------------------------------------------------------------


def test_sa006_fires_for_two_user_managed_keys():
    sa = _sa(keys=[_user_key("k1"), _user_key("k2")])
    result = analyze(sa, REF)
    assert "GCP-SA-006" in _check_ids(result)


def test_sa006_fires_for_three_user_managed_keys():
    sa = _sa(keys=[_user_key("k1"), _user_key("k2"), _user_key("k3")])
    result = analyze(sa, REF)
    assert "GCP-SA-006" in _check_ids(result)


def test_sa006_does_not_fire_for_one_user_managed_key():
    sa = _sa(keys=[_user_key("k1")])
    result = analyze(sa, REF)
    assert "GCP-SA-006" not in _check_ids(result)


def test_sa006_does_not_fire_with_no_keys():
    sa = _sa(keys=[])
    result = analyze(sa, REF)
    assert "GCP-SA-006" not in _check_ids(result)


def test_sa006_does_not_fire_for_two_system_managed_keys():
    sa = _sa(keys=[_sys_key("s1"), _sys_key("s2")])
    result = analyze(sa, REF)
    assert "GCP-SA-006" not in _check_ids(result)


def test_sa006_does_not_fire_for_one_user_one_system_key():
    sa = _sa(keys=[_user_key("u1"), _sys_key("s1")])
    result = analyze(sa, REF)
    assert "GCP-SA-006" not in _check_ids(result)


def test_sa006_only_one_finding_for_many_keys():
    sa = _sa(keys=[_user_key(f"k{i}") for i in range(5)])
    result = analyze(sa, REF)
    sa006_findings = [f for f in result.findings if f.check_id == "GCP-SA-006"]
    assert len(sa006_findings) == 1


def test_sa006_severity_is_medium():
    sa = _sa(keys=[_user_key("k1"), _user_key("k2")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-006")
    assert f.severity == "MEDIUM"


def test_sa006_weight_is_15():
    assert _CHECK_WEIGHTS["GCP-SA-006"] == 15


def test_sa006_detail_contains_count():
    sa = _sa(keys=[_user_key("k1"), _user_key("k2"), _user_key("k3")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-006")
    assert "3" in f.detail


def test_sa006_detail_contains_key_ids():
    sa = _sa(keys=[_user_key("alpha"), _user_key("beta")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-006")
    assert "alpha" in f.detail
    assert "beta" in f.detail


# ---------------------------------------------------------------------------
# GCP-SA-007: role binding at organization or folder level
# ---------------------------------------------------------------------------


def test_sa007_fires_for_org_level_binding():
    sa = _sa(role_bindings=[_binding("roles/viewer", "organization", "org-111")])
    result = analyze(sa, REF)
    assert "GCP-SA-007" in _check_ids(result)


def test_sa007_fires_for_folder_level_binding():
    sa = _sa(role_bindings=[_binding("roles/viewer", "folder", "folder-222")])
    result = analyze(sa, REF)
    assert "GCP-SA-007" in _check_ids(result)


def test_sa007_does_not_fire_for_project_level_binding():
    sa = _sa(role_bindings=[_binding("roles/viewer", "project", "proj-1")])
    result = analyze(sa, REF)
    assert "GCP-SA-007" not in _check_ids(result)


def test_sa007_does_not_fire_for_bucket_level_binding():
    sa = _sa(role_bindings=[_binding("roles/storage.objectViewer", "bucket", "my-bucket")])
    result = analyze(sa, REF)
    assert "GCP-SA-007" not in _check_ids(result)


def test_sa007_multiple_elevated_bindings_produce_multiple_findings():
    bindings = [
        _binding("roles/viewer", "organization", "org-1"),
        _binding("roles/viewer", "folder", "folder-1"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    sa007_findings = [f for f in result.findings if f.check_id == "GCP-SA-007"]
    assert len(sa007_findings) == 2


def test_sa007_severity_is_high():
    sa = _sa(role_bindings=[_binding("roles/viewer", "organization", "org-1")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-007")
    assert f.severity == "HIGH"


def test_sa007_weight_is_20():
    assert _CHECK_WEIGHTS["GCP-SA-007"] == 20


def test_sa007_weight_counted_once_for_org_and_folder():
    bindings = [
        _binding("roles/viewer", "organization", "org-1"),
        _binding("roles/viewer", "folder", "folder-1"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    assert result.risk_score == 20


def test_sa007_detail_contains_resource_type():
    sa = _sa(role_bindings=[_binding("roles/viewer", "organization", "my-org")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-007")
    assert "organization" in f.detail


def test_sa007_detail_contains_resource_id():
    sa = _sa(role_bindings=[_binding("roles/editor", "folder", "folder-999")])
    result = analyze(sa, REF)
    f = next(f for f in result.findings if f.check_id == "GCP-SA-007")
    assert "folder-999" in f.detail


# ---------------------------------------------------------------------------
# Risk score: weight deduplication and cap at 100
# ---------------------------------------------------------------------------


def test_risk_score_zero_for_clean_sa():
    sa = _sa()
    result = analyze(sa, REF)
    assert result.risk_score == 0


def test_risk_score_capped_at_100():
    # Trigger all 7 checks to force sum > 100
    # SA-001=45, SA-002=25, SA-003=25, SA-004=25, SA-005=15, SA-006=15, SA-007=20 → sum=170
    keys = [
        _user_key("k1", created_days_ago=91, last_used_days_ago=None),  # SA-002; SA-005 suppressed
        _user_key("k2", created_days_ago=10, last_used_days_ago=None),  # SA-005, SA-006
    ]
    bindings = [
        _binding("roles/owner", "project", "p1"),                                  # SA-001
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1"),         # SA-004
        _binding("roles/viewer", "organization", "org-1"),                         # SA-007
    ]
    sa = _sa(email=_COMPUTE_EMAIL, keys=keys, role_bindings=bindings)
    result = analyze(sa, REF)
    assert result.risk_score == 100


def test_risk_score_exact_sum_when_under_100():
    # Only SA-007 fires (weight 20)
    sa = _sa(role_bindings=[_binding("roles/viewer", "folder", "f1")])
    result = analyze(sa, REF)
    assert result.risk_score == 20


def test_risk_score_sa001_and_sa007_combined():
    bindings = [
        _binding("roles/owner", "project", "p1"),    # SA-001 = 45
        _binding("roles/viewer", "folder", "f1"),    # SA-007 = 20
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    assert result.risk_score == 65


# ---------------------------------------------------------------------------
# GCPSAResult helper methods
# ---------------------------------------------------------------------------


def test_to_dict_structure():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    d = result.to_dict()
    assert "sa_email" in d
    assert "risk_score" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)


def test_to_dict_finding_keys():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    d = result.to_dict()
    f = d["findings"][0]
    assert set(f.keys()) == {"check_id", "severity", "title", "detail", "weight"}


def test_to_dict_sa_email_matches():
    sa = _sa(email="foo@bar.iam.gserviceaccount.com")
    result = analyze(sa, REF)
    assert result.to_dict()["sa_email"] == "foo@bar.iam.gserviceaccount.com"


def test_summary_contains_email():
    sa = _sa(email="summary-test@proj.iam.gserviceaccount.com")
    result = analyze(sa, REF)
    assert "summary-test@proj.iam.gserviceaccount.com" in result.summary()


def test_summary_contains_risk_score():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    assert "45" in result.summary()


def test_summary_contains_finding_count():
    sa = _sa(role_bindings=[
        _binding("roles/owner", "project", "p1"),
        _binding("roles/editor", "project", "p2"),
    ])
    result = analyze(sa, REF)
    assert "2" in result.summary()


def test_by_severity_groups_correctly():
    bindings = [
        _binding("roles/owner", "project", "p1"),       # CRITICAL
        _binding("roles/viewer", "folder", "f1"),        # HIGH (SA-007)
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    by_sev = result.by_severity()
    assert "CRITICAL" in by_sev
    assert "HIGH" in by_sev
    assert all(f.severity == "CRITICAL" for f in by_sev["CRITICAL"])
    assert all(f.severity == "HIGH" for f in by_sev["HIGH"])


def test_by_severity_returns_empty_dict_for_clean_sa():
    sa = _sa()
    result = analyze(sa, REF)
    assert result.by_severity() == {}


def test_to_dict_empty_findings_for_clean_sa():
    sa = _sa()
    result = analyze(sa, REF)
    assert result.to_dict()["findings"] == []
    assert result.to_dict()["risk_score"] == 0


# ---------------------------------------------------------------------------
# analyze_many
# ---------------------------------------------------------------------------


def test_analyze_many_returns_list_of_results():
    sas = [_sa(email=f"sa{i}@proj.iam.gserviceaccount.com") for i in range(3)]
    results = analyze_many(sas, REF)
    assert isinstance(results, list)
    assert len(results) == 3


def test_analyze_many_preserves_order():
    sas = [
        _sa(email="first@proj.iam.gserviceaccount.com"),
        _sa(email="second@proj.iam.gserviceaccount.com"),
    ]
    results = analyze_many(sas, REF)
    assert results[0].sa_email == "first@proj.iam.gserviceaccount.com"
    assert results[1].sa_email == "second@proj.iam.gserviceaccount.com"


def test_analyze_many_empty_list():
    results = analyze_many([], REF)
    assert results == []


def test_analyze_many_respects_disabled_flag():
    sas = [
        _sa(email="active@p.iam.gserviceaccount.com",
            role_bindings=[_binding("roles/owner", "project", "p1")]),
        _sa(email="disabled@p.iam.gserviceaccount.com",
            disabled=True,
            role_bindings=[_binding("roles/owner", "project", "p1")]),
    ]
    results = analyze_many(sas, REF)
    assert results[0].risk_score == 45
    assert results[1].risk_score == 0


def test_analyze_many_propagates_reference_date():
    # Key created 91 days before REF should fire SA-002 with REF as reference_date
    sa = _sa(keys=[_user_key("k1", created_days_ago=91)])
    results = analyze_many([sa], REF)
    assert "GCP-SA-002" in _check_ids(results[0])


# ---------------------------------------------------------------------------
# Reference date defaults
# ---------------------------------------------------------------------------


def test_default_reference_date_is_used_when_none():
    # Create a key that is 200 days old relative to today — must fire SA-002
    today = date.today()
    old_date = date.fromordinal(today.toordinal() - 200)
    key = GCPSAKey(
        key_id="k1",
        key_type="USER_MANAGED",
        created_date=old_date,
        last_used_date=None,
    )
    sa = _sa(keys=[key])
    result = analyze(sa, reference_date=None)  # should default to date.today()
    assert "GCP-SA-002" in _check_ids(result)


# ---------------------------------------------------------------------------
# Cross-check interaction edge cases
# ---------------------------------------------------------------------------


def test_sa001_and_sa004_can_fire_together():
    bindings = [
        _binding("roles/owner", "project", "p1"),
        _binding("roles/iam.serviceAccountTokenCreator", "project", "p1"),
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    ids = _unique_check_ids(result)
    assert "GCP-SA-001" in ids
    assert "GCP-SA-004" in ids
    assert result.risk_score == 45 + 25  # SA-001 + SA-004


def test_sa002_and_sa006_fire_together_for_two_old_keys():
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=95),
        _user_key("k2", created_days_ago=100),
    ])
    result = analyze(sa, REF)
    ids = _unique_check_ids(result)
    assert "GCP-SA-002" in ids
    assert "GCP-SA-006" in ids
    assert result.risk_score == 25 + 15  # SA-002 + SA-006


def test_sa003_and_sa001_can_fire_together_for_compute_sa_with_owner():
    sa = _sa(
        email=_COMPUTE_EMAIL,
        role_bindings=[_binding("roles/owner", "project", "p1")],
    )
    result = analyze(sa, REF)
    ids = _unique_check_ids(result)
    assert "GCP-SA-001" in ids
    assert "GCP-SA-003" in ids


def test_sa007_and_sa001_both_fire_for_owner_at_both_levels():
    bindings = [
        _binding("roles/owner", "project", "p1"),        # SA-001
        _binding("roles/owner", "organization", "org1"), # SA-007 only (not SA-001)
    ]
    sa = _sa(role_bindings=bindings)
    result = analyze(sa, REF)
    ids = _unique_check_ids(result)
    assert "GCP-SA-001" in ids
    assert "GCP-SA-007" in ids
    assert "GCP-SA-001" not in [
        f.check_id for f in result.findings
        if f.check_id == "GCP-SA-001"
        and "organization" in f.detail
    ]


# ---------------------------------------------------------------------------
# Additional edge cases and coverage tests
# ---------------------------------------------------------------------------


def test_sa_email_stored_in_result():
    email = "my-service@project-123.iam.gserviceaccount.com"
    sa = _sa(email=email)
    result = analyze(sa, REF)
    assert result.sa_email == email


def test_findings_list_is_empty_for_clean_sa():
    sa = _sa()
    result = analyze(sa, REF)
    assert result.findings == []


def test_finding_has_non_empty_title():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    for f in result.findings:
        assert len(f.title) > 0


def test_finding_has_non_empty_detail():
    sa = _sa(role_bindings=[_binding("roles/owner", "project", "p1")])
    result = analyze(sa, REF)
    for f in result.findings:
        assert len(f.detail) > 0


def test_sa002_boundary_exactly_91_days():
    # Exactly 91 days old — must fire
    sa = _sa(keys=[_user_key("k-exact", created_days_ago=91)])
    result = analyze(sa, REF)
    assert "GCP-SA-002" in _check_ids(result)


def test_sa005_boundary_exactly_8_days():
    # Exactly 8 days old — must fire
    sa = _sa(keys=[_user_key("k-8", created_days_ago=8, last_used_days_ago=None)])
    result = analyze(sa, REF)
    assert "GCP-SA-005" in _check_ids(result)


def test_sa001_does_not_fire_for_bucket_resource_type():
    # roles/owner on a bucket is not a project-level binding
    sa = _sa(role_bindings=[_binding("roles/owner", "bucket", "my-bucket")])
    result = analyze(sa, REF)
    assert "GCP-SA-001" not in _check_ids(result)


def test_sa004_does_not_fire_for_roles_iam_admin():
    # roles/iam.admin is privileged but is not an impersonation role
    sa = _sa(role_bindings=[_binding("roles/iam.admin", "project", "p1")])
    result = analyze(sa, REF)
    assert "GCP-SA-004" not in _check_ids(result)


def test_sa006_fires_for_two_user_managed_one_system():
    # 2 user-managed + 1 system → SA-006 must fire
    sa = _sa(keys=[_user_key("u1"), _user_key("u2"), _sys_key("s1")])
    result = analyze(sa, REF)
    assert "GCP-SA-006" in _check_ids(result)


def test_sa007_does_not_fire_for_bigquery_resource_type():
    sa = _sa(role_bindings=[_binding("roles/bigquery.admin", "dataset", "ds1")])
    result = analyze(sa, REF)
    assert "GCP-SA-007" not in _check_ids(result)


def test_risk_score_sa002_sa006_is_40():
    # 2 old user-managed keys: SA-002 (25) + SA-006 (15) = 40
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=91, last_used_days_ago=5),
        _user_key("k2", created_days_ago=95, last_used_days_ago=5),
    ])
    result = analyze(sa, REF)
    assert result.risk_score == 40


def test_all_seven_check_ids_present_in_weights():
    for i in range(1, 8):
        cid = f"GCP-SA-00{i}"
        assert cid in _CHECK_WEIGHTS, f"{cid} missing from _CHECK_WEIGHTS"


def test_sa003_fires_with_org_level_binding_on_compute_sa():
    # SA-003 is triggered by any non-empty role_bindings list, even org-level
    sa = _sa(
        email=_COMPUTE_EMAIL,
        role_bindings=[_binding("roles/viewer", "organization", "org-1")],
    )
    result = analyze(sa, REF)
    ids = _unique_check_ids(result)
    assert "GCP-SA-003" in ids
    assert "GCP-SA-007" in ids


def test_by_severity_medium_bucket_contains_sa005_and_sa006():
    sa = _sa(keys=[
        _user_key("k1", created_days_ago=10, last_used_days_ago=None),
        _user_key("k2", created_days_ago=12, last_used_days_ago=None),
    ])
    result = analyze(sa, REF)
    by_sev = result.by_severity()
    medium_ids = {f.check_id for f in by_sev.get("MEDIUM", [])}
    assert "GCP-SA-005" in medium_ids
    assert "GCP-SA-006" in medium_ids


def test_analyze_many_mixed_disabled_and_active():
    sas = [
        _sa(email="a@p.iam.gserviceaccount.com",
            keys=[_user_key("k1", created_days_ago=100)]),
        _sa(email="b@p.iam.gserviceaccount.com", disabled=True,
            keys=[_user_key("k1", created_days_ago=100)]),
        _sa(email="c@p.iam.gserviceaccount.com",
            role_bindings=[_binding("roles/viewer", "folder", "f1")]),
    ]
    results = analyze_many(sas, REF)
    assert results[0].risk_score > 0
    assert results[1].risk_score == 0
    assert results[2].risk_score == 20


def test_sa_with_no_keys_and_no_bindings_has_zero_risk():
    sa = _sa(keys=[], role_bindings=[])
    result = analyze(sa, REF)
    assert result.risk_score == 0
    assert result.findings == []
