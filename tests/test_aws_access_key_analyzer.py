# test_aws_access_key_analyzer.py
# Part of Cyber Port — IAM Audit Lab
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See https://creativecommons.org/licenses/by/4.0/ for details.
#
# Test suite for aws_access_key_analyzer.py
# Run with:  python -m pytest tests/test_aws_access_key_analyzer.py -q

import sys
import os

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import date
from typing import List, Optional

from analyzers.aws_access_key_analyzer import (
    AccessKey,
    AKFinding,
    AKResult,
    IAMUserKeyContext,
    _CHECK_WEIGHTS,
    analyze,
    analyze_many,
)

# ---------------------------------------------------------------------------
# Fixed reference date — avoids flakiness as time passes
# ---------------------------------------------------------------------------
REF = date(2026, 4, 6)


# ---------------------------------------------------------------------------
# Builder helpers — keep individual tests short and readable
# ---------------------------------------------------------------------------

def _key(
    key_id: str = "****TEST",
    status: str = "Active",
    created_days_ago: int = 30,
    last_used_days_ago: Optional[int] = 10,
) -> AccessKey:
    """Create an AccessKey relative to the fixed reference date."""
    created = date.fromordinal(REF.toordinal() - created_days_ago)
    last_used: Optional[date] = None
    if last_used_days_ago is not None:
        last_used = date.fromordinal(REF.toordinal() - last_used_days_ago)
    return AccessKey(
        key_id=key_id,
        status=status,
        created_date=created,
        last_used_date=last_used,
    )


def _user(
    username: str = "alice",
    is_root: bool = False,
    console_access: bool = False,
    mfa_active: bool = True,
    user_active: bool = True,
    access_keys: Optional[List[AccessKey]] = None,
) -> IAMUserKeyContext:
    """Create an IAMUserKeyContext with sensible defaults."""
    return IAMUserKeyContext(
        username=username,
        is_root=is_root,
        console_access=console_access,
        mfa_active=mfa_active,
        user_active=user_active,
        access_keys=access_keys if access_keys is not None else [],
    )


def _check_ids(result: AKResult) -> List[str]:
    return [f.check_id for f in result.findings]


# ===========================================================================
# AK-001 — Root account has one or more active access keys
# ===========================================================================

def test_ak001_root_with_one_active_key_fires():
    u = _user(username="<root_account>", is_root=True, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-001" in _check_ids(r)


def test_ak001_root_with_two_active_keys_fires_once():
    keys = [_key("****AAA"), _key("****BBB")]
    u = _user(username="<root_account>", is_root=True, access_keys=keys)
    r = analyze(u, REF)
    # AK-001 fires exactly once regardless of key count
    assert _check_ids(r).count("AK-001") == 1


def test_ak001_root_with_no_keys_does_not_fire():
    u = _user(username="<root_account>", is_root=True, access_keys=[])
    r = analyze(u, REF)
    assert "AK-001" not in _check_ids(r)


def test_ak001_root_with_only_inactive_key_does_not_fire():
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(status="Inactive")],
    )
    r = analyze(u, REF)
    assert "AK-001" not in _check_ids(r)


def test_ak001_non_root_with_active_key_does_not_fire():
    u = _user(is_root=False, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-001" not in _check_ids(r)


def test_ak001_severity_is_critical():
    u = _user(username="<root_account>", is_root=True, access_keys=[_key()])
    r = analyze(u, REF)
    finding = next(f for f in r.findings if f.check_id == "AK-001")
    assert finding.severity == "CRITICAL"


def test_ak001_weight_is_45():
    assert _CHECK_WEIGHTS["AK-001"] == 45


def test_ak001_contributes_45_to_risk_score():
    # Only AK-001-eligible setup: root + fresh active key (no other check fires)
    # fresh key: 5 days old, last used 1 day ago — avoids AK-002/003/004/007
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    assert r.risk_score == 45


# ===========================================================================
# AK-002 — Access key age exceeds 90 days
# ===========================================================================

def test_ak002_key_91_days_old_fires():
    u = _user(access_keys=[_key(created_days_ago=91, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert "AK-002" in _check_ids(r)


def test_ak002_key_exactly_90_days_old_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=90, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert "AK-002" not in _check_ids(r)


def test_ak002_key_89_days_old_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=89, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert "AK-002" not in _check_ids(r)


def test_ak002_inactive_key_does_not_fire():
    u = _user(access_keys=[_key(status="Inactive", created_days_ago=200, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert "AK-002" not in _check_ids(r)


def test_ak002_two_old_keys_produce_two_findings():
    keys = [
        _key("****AAA", created_days_ago=100, last_used_days_ago=1),
        _key("****BBB", created_days_ago=120, last_used_days_ago=1),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert _check_ids(r).count("AK-002") == 2


def test_ak002_two_old_keys_weight_counted_once():
    keys = [
        _key("****AAA", created_days_ago=100, last_used_days_ago=1),
        _key("****BBB", created_days_ago=120, last_used_days_ago=1),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    # Two findings but weight deduplication: score = AK-002(25) + AK-005(15) = 40
    fired = {f.check_id for f in r.findings}
    expected = sum(_CHECK_WEIGHTS[cid] for cid in fired)
    assert r.risk_score == min(100, expected)


def test_ak002_severity_is_high():
    u = _user(access_keys=[_key(created_days_ago=91, last_used_days_ago=1)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-002")
    assert f.severity == "HIGH"


def test_ak002_detail_contains_key_id():
    u = _user(access_keys=[_key("****ZZZZ", created_days_ago=91, last_used_days_ago=1)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-002")
    assert "****ZZZZ" in f.detail


def test_ak002_weight_is_25():
    assert _CHECK_WEIGHTS["AK-002"] == 25


# ===========================================================================
# AK-003 — Key never used and older than 7 days
# ===========================================================================

def test_ak003_never_used_8_days_old_fires():
    u = _user(access_keys=[_key(created_days_ago=8, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" in _check_ids(r)


def test_ak003_never_used_exactly_7_days_old_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=7, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" not in _check_ids(r)


def test_ak003_never_used_6_days_old_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=6, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" not in _check_ids(r)


def test_ak003_key_with_last_used_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=100, last_used_days_ago=5)])
    r = analyze(u, REF)
    assert "AK-003" not in _check_ids(r)


def test_ak003_inactive_never_used_key_does_not_fire():
    u = _user(access_keys=[_key(status="Inactive", created_days_ago=30, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" not in _check_ids(r)


def test_ak003_two_never_used_old_keys_produce_two_findings():
    keys = [
        _key("****CCC", created_days_ago=20, last_used_days_ago=None),
        _key("****DDD", created_days_ago=30, last_used_days_ago=None),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert _check_ids(r).count("AK-003") == 2


def test_ak003_weight_counted_once_for_two_keys():
    keys = [
        _key("****CCC", created_days_ago=20, last_used_days_ago=None),
        _key("****DDD", created_days_ago=30, last_used_days_ago=None),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    fired = {f.check_id for f in r.findings}
    expected = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired))
    assert r.risk_score == expected


def test_ak003_severity_is_high():
    u = _user(access_keys=[_key(created_days_ago=10, last_used_days_ago=None)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-003")
    assert f.severity == "HIGH"


def test_ak003_detail_contains_key_id():
    u = _user(access_keys=[_key("****NEVR", created_days_ago=10, last_used_days_ago=None)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-003")
    assert "****NEVR" in f.detail


def test_ak003_weight_is_20():
    assert _CHECK_WEIGHTS["AK-003"] == 20


# ===========================================================================
# AK-004 — Key last used > 90 days ago
# ===========================================================================

def test_ak004_last_used_91_days_ago_fires():
    u = _user(access_keys=[_key(created_days_ago=100, last_used_days_ago=91)])
    r = analyze(u, REF)
    assert "AK-004" in _check_ids(r)


def test_ak004_last_used_exactly_90_days_ago_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=100, last_used_days_ago=90)])
    r = analyze(u, REF)
    assert "AK-004" not in _check_ids(r)


def test_ak004_last_used_89_days_ago_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=100, last_used_days_ago=89)])
    r = analyze(u, REF)
    assert "AK-004" not in _check_ids(r)


def test_ak004_suppressed_when_ak003_fires():
    # Key never used (last_used=None) and older than 7 days — AK-003 fires, AK-004 must not
    u = _user(access_keys=[_key(created_days_ago=100, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" in _check_ids(r)
    assert "AK-004" not in _check_ids(r)


def test_ak004_not_suppressed_for_different_key():
    # Key A: never used (AK-003), Key B: last used 100 days ago (AK-004 should fire)
    keys = [
        _key("****NVR", created_days_ago=15, last_used_days_ago=None),
        _key("****OLD", created_days_ago=200, last_used_days_ago=100),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert "AK-003" in _check_ids(r)
    assert "AK-004" in _check_ids(r)


def test_ak004_inactive_key_does_not_fire():
    u = _user(access_keys=[_key(status="Inactive", created_days_ago=200, last_used_days_ago=100)])
    r = analyze(u, REF)
    assert "AK-004" not in _check_ids(r)


def test_ak004_severity_is_medium():
    u = _user(access_keys=[_key(created_days_ago=200, last_used_days_ago=100)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-004")
    assert f.severity == "MEDIUM"


def test_ak004_detail_contains_key_id():
    u = _user(access_keys=[_key("****STALE", created_days_ago=200, last_used_days_ago=100)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-004")
    assert "****STALE" in f.detail


def test_ak004_weight_is_15():
    assert _CHECK_WEIGHTS["AK-004"] == 15


def test_ak004_two_stale_keys_two_findings_weight_once():
    keys = [
        _key("****EEE", created_days_ago=200, last_used_days_ago=100),
        _key("****FFF", created_days_ago=200, last_used_days_ago=120),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert _check_ids(r).count("AK-004") == 2
    fired = {f.check_id for f in r.findings}
    assert r.risk_score == min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired))


# ===========================================================================
# AK-005 — User has multiple active access keys
# ===========================================================================

def test_ak005_two_active_keys_fires():
    keys = [_key("****111"), _key("****222")]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert "AK-005" in _check_ids(r)


def test_ak005_three_active_keys_fires_once():
    keys = [_key("****111"), _key("****222"), _key("****333")]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert _check_ids(r).count("AK-005") == 1


def test_ak005_one_active_key_does_not_fire():
    u = _user(access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-005" not in _check_ids(r)


def test_ak005_no_active_keys_does_not_fire():
    u = _user(access_keys=[_key(status="Inactive"), _key(status="Inactive")])
    r = analyze(u, REF)
    assert "AK-005" not in _check_ids(r)


def test_ak005_one_active_one_inactive_does_not_fire():
    keys = [_key("****ACT"), _key("****INA", status="Inactive")]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert "AK-005" not in _check_ids(r)


def test_ak005_severity_is_medium():
    keys = [_key("****111"), _key("****222")]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-005")
    assert f.severity == "MEDIUM"


def test_ak005_weight_is_15():
    assert _CHECK_WEIGHTS["AK-005"] == 15


def test_ak005_detail_contains_both_key_ids():
    keys = [_key("****KK1"), _key("****KK2")]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-005")
    assert "****KK1" in f.detail
    assert "****KK2" in f.detail


# ===========================================================================
# AK-006 — Console access + active key + no MFA
# ===========================================================================

def test_ak006_console_active_key_no_mfa_fires():
    u = _user(console_access=True, mfa_active=False, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-006" in _check_ids(r)


def test_ak006_console_active_key_with_mfa_does_not_fire():
    u = _user(console_access=True, mfa_active=True, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-006" not in _check_ids(r)


def test_ak006_no_console_no_mfa_active_key_does_not_fire():
    u = _user(console_access=False, mfa_active=False, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-006" not in _check_ids(r)


def test_ak006_console_no_mfa_no_active_key_does_not_fire():
    u = _user(
        console_access=True,
        mfa_active=False,
        access_keys=[_key(status="Inactive")],
    )
    r = analyze(u, REF)
    assert "AK-006" not in _check_ids(r)


def test_ak006_console_no_mfa_no_keys_at_all_does_not_fire():
    u = _user(console_access=True, mfa_active=False, access_keys=[])
    r = analyze(u, REF)
    assert "AK-006" not in _check_ids(r)


def test_ak006_fires_once_with_two_active_keys():
    keys = [_key("****XX1"), _key("****XX2")]
    u = _user(console_access=True, mfa_active=False, access_keys=keys)
    r = analyze(u, REF)
    assert _check_ids(r).count("AK-006") == 1


def test_ak006_severity_is_high():
    u = _user(console_access=True, mfa_active=False, access_keys=[_key()])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-006")
    assert f.severity == "HIGH"


def test_ak006_weight_is_25():
    assert _CHECK_WEIGHTS["AK-006"] == 25


def test_ak006_detail_contains_key_id():
    u = _user(console_access=True, mfa_active=False, access_keys=[_key("****MFA0")])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-006")
    assert "****MFA0" in f.detail


# ===========================================================================
# AK-007 — Active key on an inactive user
# ===========================================================================

def test_ak007_inactive_user_active_key_fires():
    u = _user(user_active=False, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-007" in _check_ids(r)


def test_ak007_active_user_active_key_does_not_fire():
    u = _user(user_active=True, access_keys=[_key()])
    r = analyze(u, REF)
    assert "AK-007" not in _check_ids(r)


def test_ak007_inactive_user_inactive_key_does_not_fire():
    u = _user(user_active=False, access_keys=[_key(status="Inactive")])
    r = analyze(u, REF)
    assert "AK-007" not in _check_ids(r)


def test_ak007_inactive_user_no_keys_does_not_fire():
    u = _user(user_active=False, access_keys=[])
    r = analyze(u, REF)
    assert "AK-007" not in _check_ids(r)


def test_ak007_two_active_keys_two_findings():
    keys = [_key("****D11"), _key("****D22")]
    u = _user(user_active=False, access_keys=keys)
    r = analyze(u, REF)
    assert _check_ids(r).count("AK-007") == 2


def test_ak007_weight_counted_once_for_two_keys():
    keys = [_key("****D11"), _key("****D22")]
    u = _user(user_active=False, access_keys=keys)
    r = analyze(u, REF)
    fired = {f.check_id for f in r.findings}
    assert r.risk_score == min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired))


def test_ak007_severity_is_high():
    u = _user(user_active=False, access_keys=[_key()])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-007")
    assert f.severity == "HIGH"


def test_ak007_weight_is_20():
    assert _CHECK_WEIGHTS["AK-007"] == 20


def test_ak007_detail_contains_key_id():
    u = _user(user_active=False, access_keys=[_key("****DKEY")])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-007")
    assert "****DKEY" in f.detail


# ===========================================================================
# Risk score — weight deduplication and capping
# ===========================================================================

def test_risk_score_zero_for_clean_user():
    # Fresh key, recently used, single key, no console, active user
    u = _user(access_keys=[_key(created_days_ago=5, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert r.risk_score == 0


def test_risk_score_capped_at_100():
    # Fire as many checks as possible to exceed 100 in raw sum
    keys = [
        _key("****P11", created_days_ago=200, last_used_days_ago=None),
        _key("****P22", created_days_ago=200, last_used_days_ago=None),
    ]
    u = _user(
        username="<root_account>",
        is_root=True,
        console_access=True,
        mfa_active=False,
        user_active=False,
        access_keys=keys,
    )
    r = analyze(u, REF)
    assert r.risk_score == 100


def test_risk_score_uses_unique_check_ids():
    # AK-002 fires twice (two old keys) but should contribute 25 only once
    keys = [
        _key("****A1", created_days_ago=100, last_used_days_ago=1),
        _key("****A2", created_days_ago=110, last_used_days_ago=1),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    fired = {f.check_id for f in r.findings}
    assert r.risk_score == min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired))


def test_risk_score_single_check_ak001():
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    # Only AK-001 should fire in this configuration
    assert r.risk_score == 45


def test_risk_score_ak002_plus_ak005():
    keys = [
        _key("****B1", created_days_ago=100, last_used_days_ago=1),
        _key("****B2", created_days_ago=100, last_used_days_ago=1),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    # AK-002(25) + AK-005(15) = 40
    assert r.risk_score == 40


# ===========================================================================
# AKResult helper methods
# ===========================================================================

def test_to_dict_returns_dict():
    u = _user(access_keys=[_key()])
    r = analyze(u, REF)
    d = r.to_dict()
    assert isinstance(d, dict)
    assert "username" in d
    assert "risk_score" in d
    assert "findings" in d


def test_to_dict_findings_are_list_of_dicts():
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    d = r.to_dict()
    assert isinstance(d["findings"], list)
    assert all(isinstance(f, dict) for f in d["findings"])


def test_to_dict_finding_has_required_keys():
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    f = r.to_dict()["findings"][0]
    for key in ("check_id", "severity", "title", "detail", "weight"):
        assert key in f


def test_summary_contains_username():
    u = _user(username="test-user", access_keys=[_key()])
    r = analyze(u, REF)
    assert "test-user" in r.summary()


def test_summary_contains_risk_score():
    u = _user(access_keys=[_key()])
    r = analyze(u, REF)
    assert str(r.risk_score) in r.summary()


def test_by_severity_groups_correctly():
    # AK-001 (CRITICAL) + AK-002 (HIGH) setup
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=100, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    grouped = r.by_severity()
    assert "CRITICAL" in grouped
    assert "HIGH" in grouped
    assert all(f.severity == "CRITICAL" for f in grouped["CRITICAL"])
    assert all(f.severity == "HIGH" for f in grouped["HIGH"])


def test_by_severity_returns_dict():
    u = _user(access_keys=[_key()])
    r = analyze(u, REF)
    assert isinstance(r.by_severity(), dict)


def test_clean_user_has_empty_findings():
    u = _user(access_keys=[_key(created_days_ago=5, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert r.findings == []


# ===========================================================================
# analyze_many — batch function
# ===========================================================================

def test_analyze_many_returns_list():
    users = [_user("alice"), _user("bob")]
    results = analyze_many(users, REF)
    assert isinstance(results, list)


def test_analyze_many_length_matches_input():
    users = [_user(f"user{i}") for i in range(5)]
    results = analyze_many(users, REF)
    assert len(results) == 5


def test_analyze_many_preserves_order():
    users = [_user(f"u{i}") for i in range(4)]
    results = analyze_many(users, REF)
    for i, r in enumerate(results):
        assert r.username == f"u{i}"


def test_analyze_many_empty_list():
    results = analyze_many([], REF)
    assert results == []


def test_analyze_many_uses_reference_date():
    # If reference_date is forwarded, a key 91 days old should fire AK-002
    keys = [_key(created_days_ago=91, last_used_days_ago=1)]
    users = [_user(access_keys=keys)]
    results = analyze_many(users, reference_date=REF)
    assert "AK-002" in _check_ids(results[0])


def test_analyze_many_independent_results():
    # One clean user and one with a finding — ensure they don't bleed into each other
    clean = _user("clean", access_keys=[_key(created_days_ago=5, last_used_days_ago=1)])
    dirty = _user("dirty", access_keys=[_key(created_days_ago=91, last_used_days_ago=1)])
    results = analyze_many([clean, dirty], REF)
    clean_r = next(r for r in results if r.username == "clean")
    dirty_r = next(r for r in results if r.username == "dirty")
    assert clean_r.risk_score == 0
    assert "AK-002" in _check_ids(dirty_r)


# ===========================================================================
# Edge cases and combined scenarios
# ===========================================================================

def test_user_with_no_keys_has_no_findings():
    u = _user(console_access=True, mfa_active=False, access_keys=[])
    r = analyze(u, REF)
    assert r.findings == []
    assert r.risk_score == 0


def test_only_inactive_keys_no_findings():
    keys = [
        _key("****I1", status="Inactive", created_days_ago=200, last_used_days_ago=None),
        _key("****I2", status="Inactive", created_days_ago=200, last_used_days_ago=100),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert r.findings == []


def test_all_checks_can_fire_together():
    # Construct a worst-case user firing all applicable checks
    keys = [
        _key("****W1", created_days_ago=200, last_used_days_ago=None),
        _key("****W2", created_days_ago=200, last_used_days_ago=None),
    ]
    u = _user(
        username="<root_account>",
        is_root=True,
        console_access=True,
        mfa_active=False,
        user_active=False,
        access_keys=keys,
    )
    r = analyze(u, REF)
    fired = {f.check_id for f in r.findings}
    # AK-001, AK-002, AK-003, AK-005, AK-006, AK-007 should all be present
    assert "AK-001" in fired
    assert "AK-002" in fired
    assert "AK-003" in fired
    assert "AK-005" in fired
    assert "AK-006" in fired
    assert "AK-007" in fired


def test_ak003_and_ak004_mutually_exclusive_same_key():
    # A never-used key: AK-003 fires, AK-004 must NOT fire for the same key
    u = _user(access_keys=[_key(created_days_ago=200, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" in _check_ids(r)
    assert "AK-004" not in _check_ids(r)


def test_ak002_and_ak003_can_fire_together_same_key():
    # Key > 90 days old AND never used > 7 days => both AK-002 and AK-003 fire
    u = _user(access_keys=[_key(created_days_ago=100, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-002" in _check_ids(r)
    assert "AK-003" in _check_ids(r)


def test_reference_date_boundary_ak002():
    # A key created exactly 91 days before the reference date
    created = date.fromordinal(REF.toordinal() - 91)
    key = AccessKey(key_id="****BDY", status="Active", created_date=created, last_used_date=REF)
    u = _user(access_keys=[key])
    r = analyze(u, reference_date=REF)
    assert "AK-002" in _check_ids(r)


def test_reference_date_boundary_ak003():
    # A key created exactly 8 days before the reference date, never used
    created = date.fromordinal(REF.toordinal() - 8)
    key = AccessKey(key_id="****BDN", status="Active", created_date=created, last_used_date=None)
    u = _user(access_keys=[key])
    r = analyze(u, reference_date=REF)
    assert "AK-003" in _check_ids(r)


def test_reference_date_default_does_not_raise():
    # Passing no reference_date should use date.today() without error
    u = _user(access_keys=[_key()])
    r = analyze(u)  # No reference_date argument
    assert isinstance(r, AKResult)


def test_finding_weight_matches_check_weights_dict():
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-001")
    assert f.weight == _CHECK_WEIGHTS["AK-001"]


def test_ak006_and_ak007_can_fire_together():
    # Inactive user + console + no MFA + active key
    u = _user(
        console_access=True,
        mfa_active=False,
        user_active=False,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    assert "AK-006" in _check_ids(r)
    assert "AK-007" in _check_ids(r)


def test_username_preserved_in_result():
    u = _user(username="specific-name", access_keys=[])
    r = analyze(u, REF)
    assert r.username == "specific-name"


def test_ak004_fires_for_key_used_91_days_ago_not_ak003():
    # last_used is not None, so AK-003 should NOT fire; AK-004 should fire
    u = _user(access_keys=[_key(created_days_ago=200, last_used_days_ago=91)])
    r = analyze(u, REF)
    assert "AK-004" in _check_ids(r)
    assert "AK-003" not in _check_ids(r)


# ===========================================================================
# Additional coverage — data model, mixed states, boundary arithmetic
# ===========================================================================

def test_accesskey_dataclass_fields():
    k = AccessKey(
        key_id="****ABCD",
        status="Active",
        created_date=date(2026, 1, 1),
        last_used_date=date(2026, 3, 1),
    )
    assert k.key_id == "****ABCD"
    assert k.status == "Active"
    assert k.created_date == date(2026, 1, 1)
    assert k.last_used_date == date(2026, 3, 1)


def test_accesskey_last_used_none_allowed():
    k = AccessKey(
        key_id="****NONE",
        status="Active",
        created_date=date(2026, 1, 1),
        last_used_date=None,
    )
    assert k.last_used_date is None


def test_iamuserkeycontext_dataclass_fields():
    u = _user(username="charlie", is_root=False, console_access=True, mfa_active=False, user_active=True)
    assert u.username == "charlie"
    assert u.is_root is False
    assert u.console_access is True
    assert u.mfa_active is False
    assert u.user_active is True


def test_akresult_default_findings_empty():
    r = AKResult(username="test")
    assert r.findings == []
    assert r.risk_score == 0


def test_akfinding_all_fields_set():
    f = AKFinding(check_id="AK-001", severity="CRITICAL", title="Title", detail="Detail", weight=45)
    assert f.check_id == "AK-001"
    assert f.severity == "CRITICAL"
    assert f.weight == 45


def test_ak002_key_365_days_old_fires():
    u = _user(access_keys=[_key(created_days_ago=365, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert "AK-002" in _check_ids(r)


def test_ak003_never_used_exactly_8_days_old_fires():
    u = _user(access_keys=[_key(created_days_ago=8, last_used_days_ago=None)])
    r = analyze(u, REF)
    assert "AK-003" in _check_ids(r)


def test_ak004_key_used_yesterday_does_not_fire():
    u = _user(access_keys=[_key(created_days_ago=200, last_used_days_ago=1)])
    r = analyze(u, REF)
    assert "AK-004" not in _check_ids(r)


def test_ak005_exactly_two_active_one_inactive_fires():
    keys = [
        _key("****ACT1"),
        _key("****ACT2"),
        _key("****INA1", status="Inactive"),
    ]
    u = _user(access_keys=keys)
    r = analyze(u, REF)
    assert "AK-005" in _check_ids(r)


def test_ak006_only_inactive_key_no_fire():
    u = _user(
        console_access=True,
        mfa_active=False,
        access_keys=[_key(status="Inactive")],
    )
    r = analyze(u, REF)
    assert "AK-006" not in _check_ids(r)


def test_ak007_mixed_keys_fires_only_for_active():
    keys = [
        _key("****ACT", status="Active"),
        _key("****INA", status="Inactive"),
    ]
    u = _user(user_active=False, access_keys=keys)
    r = analyze(u, REF)
    ak007_findings = [f for f in r.findings if f.check_id == "AK-007"]
    # Only one AK-007 finding (for the Active key)
    assert len(ak007_findings) == 1
    assert "****ACT" in ak007_findings[0].detail


def test_to_dict_risk_score_matches_result():
    u = _user(
        username="<root_account>",
        is_root=True,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    assert r.to_dict()["risk_score"] == r.risk_score


def test_by_severity_empty_when_no_findings():
    u = _user(access_keys=[])
    r = analyze(u, REF)
    assert r.by_severity() == {}


def test_summary_shows_zero_findings_when_clean():
    u = _user(access_keys=[])
    r = analyze(u, REF)
    s = r.summary()
    assert "0" in s or "none" in s.lower()


def test_ak001_detail_mentions_root_username():
    u = _user(username="<root_account>", is_root=True, access_keys=[_key(created_days_ago=5, last_used_days_ago=1)])
    r = analyze(u, REF)
    f = next(f for f in r.findings if f.check_id == "AK-001")
    assert "<root_account>" in f.detail


def test_risk_score_ak006_plus_ak007_no_cap():
    # AK-006(25) + AK-007(20) = 45 — well under 100
    u = _user(
        console_access=True,
        mfa_active=False,
        user_active=False,
        access_keys=[_key(created_days_ago=5, last_used_days_ago=1)],
    )
    r = analyze(u, REF)
    fired = {f.check_id for f in r.findings}
    assert r.risk_score == min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired))
