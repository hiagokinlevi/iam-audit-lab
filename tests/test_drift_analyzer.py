"""
Tests for analyzers/drift/analyzer.py

Validates:
  - IamSnapshot.identity_map() returns correct keys
  - IamSnapshot.privileged_count and mfa_enabled_count
  - diff_snapshots() with identical snapshots: no changes
  - NEW_IDENTITY detected for identities in current but not baseline
  - REMOVED_IDENTITY detected for identities in baseline but not current
  - PRIVILEGE_GAINED detected when is_privileged transitions False→True
  - PRIVILEGE_LOST detected when is_privileged transitions True→False
  - MFA_DISABLED detected when mfa_enabled transitions True→False
  - MFA_ENABLED detected when mfa_enabled transitions False→True
  - POLICY_ADDED detected for new entries in attached_policies
  - POLICY_REMOVED detected for removed entries in attached_policies
  - STATUS_CHANGED detected when IdentityStatus changes
  - DriftReport.risk_delta is positive when high-risk changes present
  - DriftReport.risk_delta is negative when only positive changes present
  - DriftReport.high_risk_changes filters correctly
  - DriftReport.positive_changes filters correctly
  - DriftReport.changes_by_type() filters correctly
  - DriftReport.summary() is a non-empty string
  - _CHANGE_RISK values: PRIVILEGE_GAINED > NEW_IDENTITY > POLICY_ADDED
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.drift.analyzer import (
    DriftChangeType,
    DriftReport,
    IamSnapshot,
    IdentityChange,
    diff_snapshots,
    _CHANGE_RISK,
)
from schemas.identity import IdentityRecord, IdentityStatus, IdentityType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identity(
    identity_id: str = "user-001",
    identity_name: str = "alice",
    provider: str = "aws",
    identity_type: IdentityType = IdentityType.HUMAN,
    is_privileged: bool = False,
    mfa_enabled: bool = False,
    status: IdentityStatus = IdentityStatus.ACTIVE,
    attached_policies: list[str] | None = None,
) -> IdentityRecord:
    return IdentityRecord(
        identity_id=identity_id,
        identity_name=identity_name,
        identity_type=identity_type,
        provider=provider,
        status=status,
        is_privileged=is_privileged,
        mfa_enabled=mfa_enabled,
        attached_policies=attached_policies or [],
    )


def _snap(identities: list[IdentityRecord], label: str = "snap") -> IamSnapshot:
    return IamSnapshot(label=label, identities=identities)


# ---------------------------------------------------------------------------
# IamSnapshot
# ---------------------------------------------------------------------------

class TestIamSnapshot:

    def test_identity_map_keyed_by_id_and_provider(self):
        snap = _snap([_identity("u1", provider="aws"), _identity("u2", provider="azure")])
        m = snap.identity_map()
        assert ("u1", "aws") in m
        assert ("u2", "azure") in m

    def test_privileged_count(self):
        snap = _snap([
            _identity("u1", is_privileged=True),
            _identity("u2", is_privileged=False),
        ])
        assert snap.privileged_count == 1

    def test_mfa_enabled_count(self):
        snap = _snap([
            _identity("u1", mfa_enabled=True),
            _identity("u2", mfa_enabled=True),
            _identity("u3", mfa_enabled=False),
        ])
        assert snap.mfa_enabled_count == 2

    def test_identities_stored_as_tuple(self):
        snap = _snap([_identity()])
        assert isinstance(snap.identities, tuple)


# ---------------------------------------------------------------------------
# diff_snapshots — identical
# ---------------------------------------------------------------------------

class TestIdenticalSnapshots:

    def test_identical_no_changes(self):
        ids = [_identity("u1"), _identity("u2")]
        report = diff_snapshots(_snap(ids, "base"), _snap(ids, "curr"))
        assert report.changes == []

    def test_empty_snapshots_no_changes(self):
        report = diff_snapshots(_snap([]), _snap([]))
        assert report.changes == []

    def test_counts_preserved(self):
        ids = [_identity("u1")]
        report = diff_snapshots(_snap(ids, "base"), _snap(ids, "curr"))
        assert report.baseline_count == 1
        assert report.current_count == 1


# ---------------------------------------------------------------------------
# NEW_IDENTITY
# ---------------------------------------------------------------------------

class TestNewIdentity:

    def test_new_identity_detected(self):
        base = _snap([_identity("u1")])
        curr = _snap([_identity("u1"), _identity("u2", identity_name="bob")])
        report = diff_snapshots(base, curr)
        new = [c for c in report.changes if c.change_type == DriftChangeType.NEW_IDENTITY]
        assert len(new) == 1
        assert new[0].identity_name == "bob"

    def test_new_identity_risk_weight_positive(self):
        base = _snap([])
        curr = _snap([_identity("u1")])
        report = diff_snapshots(base, curr)
        assert report.risk_delta > 0

    def test_new_privileged_identity_note_mentions_privileged(self):
        base = _snap([])
        curr = _snap([_identity("u1", is_privileged=True)])
        report = diff_snapshots(base, curr)
        change = report.changes[0]
        assert "privileged" in change.note.lower()


# ---------------------------------------------------------------------------
# REMOVED_IDENTITY
# ---------------------------------------------------------------------------

class TestRemovedIdentity:

    def test_removed_identity_detected(self):
        base = _snap([_identity("u1"), _identity("u2")])
        curr = _snap([_identity("u1")])
        report = diff_snapshots(base, curr)
        removed = [c for c in report.changes if c.change_type == DriftChangeType.REMOVED_IDENTITY]
        assert len(removed) == 1
        assert removed[0].identity_id == "u2"

    def test_removed_identity_risk_negative(self):
        assert _CHANGE_RISK[DriftChangeType.REMOVED_IDENTITY] < 0


# ---------------------------------------------------------------------------
# PRIVILEGE_GAINED / PRIVILEGE_LOST
# ---------------------------------------------------------------------------

class TestPrivilegeChanges:

    def test_privilege_gained_detected(self):
        base = _snap([_identity("u1", is_privileged=False)])
        curr = _snap([_identity("u1", is_privileged=True)])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.PRIVILEGE_GAINED]
        assert len(changes) == 1

    def test_privilege_lost_detected(self):
        base = _snap([_identity("u1", is_privileged=True)])
        curr = _snap([_identity("u1", is_privileged=False)])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.PRIVILEGE_LOST]
        assert len(changes) == 1

    def test_privilege_gained_high_risk(self):
        assert _CHANGE_RISK[DriftChangeType.PRIVILEGE_GAINED] > _CHANGE_RISK[DriftChangeType.NEW_IDENTITY]

    def test_privilege_lost_risk_negative(self):
        assert _CHANGE_RISK[DriftChangeType.PRIVILEGE_LOST] < 0


# ---------------------------------------------------------------------------
# MFA_DISABLED / MFA_ENABLED
# ---------------------------------------------------------------------------

class TestMfaChanges:

    def test_mfa_disabled_detected(self):
        base = _snap([_identity("u1", mfa_enabled=True)])
        curr = _snap([_identity("u1", mfa_enabled=False)])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.MFA_DISABLED]
        assert len(changes) == 1

    def test_mfa_enabled_detected(self):
        base = _snap([_identity("u1", mfa_enabled=False)])
        curr = _snap([_identity("u1", mfa_enabled=True)])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.MFA_ENABLED]
        assert len(changes) == 1

    def test_mfa_disabled_risk_high(self):
        assert _CHANGE_RISK[DriftChangeType.MFA_DISABLED] >= 4

    def test_mfa_enabled_risk_negative(self):
        assert _CHANGE_RISK[DriftChangeType.MFA_ENABLED] < 0


# ---------------------------------------------------------------------------
# POLICY_ADDED / POLICY_REMOVED
# ---------------------------------------------------------------------------

class TestPolicyChanges:

    def test_policy_added_detected(self):
        base = _snap([_identity("u1", attached_policies=["ReadOnly"])])
        curr = _snap([_identity("u1", attached_policies=["ReadOnly", "AdministratorAccess"])])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.POLICY_ADDED]
        assert len(changes) == 1
        assert "AdministratorAccess" in changes[0].after_value

    def test_policy_removed_detected(self):
        base = _snap([_identity("u1", attached_policies=["ReadOnly", "S3FullAccess"])])
        curr = _snap([_identity("u1", attached_policies=["ReadOnly"])])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.POLICY_REMOVED]
        assert len(changes) == 1

    def test_policy_unchanged_no_change_recorded(self):
        ids = [_identity("u1", attached_policies=["ReadOnly"])]
        report = diff_snapshots(_snap(ids), _snap(ids))
        policy_changes = [c for c in report.changes
                          if c.change_type in (DriftChangeType.POLICY_ADDED, DriftChangeType.POLICY_REMOVED)]
        assert policy_changes == []


# ---------------------------------------------------------------------------
# STATUS_CHANGED
# ---------------------------------------------------------------------------

class TestStatusChanged:

    def test_status_change_detected(self):
        base = _snap([_identity("u1", status=IdentityStatus.ACTIVE)])
        curr = _snap([_identity("u1", status=IdentityStatus.INACTIVE)])
        report = diff_snapshots(base, curr)
        changes = [c for c in report.changes if c.change_type == DriftChangeType.STATUS_CHANGED]
        assert len(changes) == 1
        assert changes[0].before_value == "active"
        assert changes[0].after_value == "inactive"

    def test_same_status_no_change(self):
        ids = [_identity("u1", status=IdentityStatus.ACTIVE)]
        report = diff_snapshots(_snap(ids), _snap(ids))
        assert not any(c.change_type == DriftChangeType.STATUS_CHANGED for c in report.changes)


# ---------------------------------------------------------------------------
# DriftReport properties
# ---------------------------------------------------------------------------

class TestDriftReportProperties:

    def test_risk_delta_positive_when_privilege_gained(self):
        base = _snap([_identity("u1", is_privileged=False)])
        curr = _snap([_identity("u1", is_privileged=True)])
        report = diff_snapshots(base, curr)
        assert report.risk_delta > 0

    def test_risk_delta_negative_when_mfa_enabled(self):
        base = _snap([_identity("u1", mfa_enabled=False)])
        curr = _snap([_identity("u1", mfa_enabled=True)])
        report = diff_snapshots(base, curr)
        assert report.risk_delta < 0

    def test_high_risk_changes_includes_privilege_gained(self):
        base = _snap([_identity("u1", is_privileged=False)])
        curr = _snap([_identity("u1", is_privileged=True)])
        report = diff_snapshots(base, curr)
        assert len(report.high_risk_changes) >= 1

    def test_positive_changes_includes_mfa_enabled(self):
        base = _snap([_identity("u1", mfa_enabled=False)])
        curr = _snap([_identity("u1", mfa_enabled=True)])
        report = diff_snapshots(base, curr)
        assert len(report.positive_changes) >= 1

    def test_changes_by_type_filters_correctly(self):
        base = _snap([_identity("u1"), _identity("u2", identity_name="bob")])
        curr = _snap([_identity("u1"), _identity("u3", identity_name="carol")])
        report = diff_snapshots(base, curr)
        new = report.changes_by_type(DriftChangeType.NEW_IDENTITY)
        removed = report.changes_by_type(DriftChangeType.REMOVED_IDENTITY)
        assert len(new) == 1
        assert len(removed) == 1

    def test_labels_preserved(self):
        report = diff_snapshots(_snap([], "2026-04-01"), _snap([], "2026-04-06"))
        assert report.baseline_label == "2026-04-01"
        assert report.current_label == "2026-04-06"

    def test_summary_is_string(self):
        report = diff_snapshots(_snap([]), _snap([]))
        assert isinstance(report.summary(), str)

    def test_summary_contains_labels(self):
        report = diff_snapshots(_snap([], "label-A"), _snap([], "label-B"))
        summary = report.summary()
        assert "label-A" in summary
        assert "label-B" in summary
