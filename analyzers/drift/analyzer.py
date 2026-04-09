"""
IAM Posture Drift Detection
=============================
Compares two IAM posture snapshots (collections of IdentityRecord objects)
to identify security-relevant changes between assessment runs.

Drift categories detected:
  - NEW_IDENTITY:          An identity present in current but not in baseline.
  - REMOVED_IDENTITY:      An identity present in baseline but not in current.
  - PRIVILEGE_GAINED:      An existing identity gained is_privileged=True.
  - PRIVILEGE_LOST:        An existing identity lost is_privileged=True.
  - MFA_DISABLED:          An existing identity had MFA removed.
  - MFA_ENABLED:           An existing identity had MFA added.
  - POLICY_ADDED:          An existing identity gained new attached policies.
  - POLICY_REMOVED:        An existing identity lost attached policies.
  - STATUS_CHANGED:        An existing identity changed status (e.g., active → inactive).

Design notes:
  - Identities are matched by (identity_id, provider) — the stable primary key.
  - Snapshots are simple lists of IdentityRecord; no persistence layer required.
  - The DriftReport.risk_delta expresses whether the current posture is better
    or worse than baseline (negative = improved, positive = worsened).

Usage:
    from analyzers.drift.analyzer import diff_snapshots, IamSnapshot

    baseline = IamSnapshot(label="2026-04-01", identities=baseline_records)
    current  = IamSnapshot(label="2026-04-06", identities=current_records)

    report = diff_snapshots(baseline, current)
    print(report.summary())
    for change in report.high_risk_changes:
        print(change.change_type, change.identity_name)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from schemas.identity import IdentityRecord, IdentityStatus


# ---------------------------------------------------------------------------
# Drift change types
# ---------------------------------------------------------------------------

class DriftChangeType(str, Enum):
    """Type of change detected between two IAM snapshots."""
    NEW_IDENTITY      = "new_identity"
    REMOVED_IDENTITY  = "removed_identity"
    PRIVILEGE_GAINED  = "privilege_gained"
    PRIVILEGE_LOST    = "privilege_lost"
    MFA_DISABLED      = "mfa_disabled"
    MFA_ENABLED       = "mfa_enabled"
    POLICY_ADDED      = "policy_added"
    POLICY_REMOVED    = "policy_removed"
    STATUS_CHANGED    = "status_changed"


# Risk weight per change type (positive = bad, negative = good)
_CHANGE_RISK: dict[DriftChangeType, int] = {
    DriftChangeType.NEW_IDENTITY:      2,   # New accounts need review
    DriftChangeType.REMOVED_IDENTITY: -1,   # Removed accounts reduce attack surface
    DriftChangeType.PRIVILEGE_GAINED:  5,   # High risk — new admin access
    DriftChangeType.PRIVILEGE_LOST:   -3,   # Positive — privilege reduction
    DriftChangeType.MFA_DISABLED:      4,   # High risk — MFA removed
    DriftChangeType.MFA_ENABLED:      -2,   # Positive — MFA added
    DriftChangeType.POLICY_ADDED:      2,   # New policy could expand permissions
    DriftChangeType.POLICY_REMOVED:   -1,   # Policy removal reduces permissions
    DriftChangeType.STATUS_CHANGED:    1,   # Neutral-ish — depends on direction
}

# Change types that represent security regressions (for high_risk_changes filter)
_HIGH_RISK_TYPES = {
    DriftChangeType.PRIVILEGE_GAINED,
    DriftChangeType.MFA_DISABLED,
    DriftChangeType.NEW_IDENTITY,
}


# ---------------------------------------------------------------------------
# Snapshot and change dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IamSnapshot:
    """
    An immutable point-in-time IAM posture snapshot.

    Attributes:
        label:       Human-readable identifier (e.g., date/time or run ID).
        identities:  All IdentityRecord objects collected at this point in time.
        provider:    Optional filter — if set, documents that this snapshot
                     covers a single cloud provider.
    """
    label:       str
    identities:  tuple[IdentityRecord, ...]
    provider:    Optional[str] = None

    def __init__(self, label: str, identities: list[IdentityRecord], provider: Optional[str] = None):
        # Use object.__setattr__ because frozen=True prevents direct assignment
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "identities", tuple(identities))
        object.__setattr__(self, "provider", provider)

    def identity_map(self) -> dict[tuple[str, str], IdentityRecord]:
        """Return a dict keyed by (identity_id, provider) for fast lookup."""
        return {(r.identity_id, r.provider): r for r in self.identities}

    @property
    def privileged_count(self) -> int:
        return sum(1 for i in self.identities if i.is_privileged)

    @property
    def mfa_enabled_count(self) -> int:
        return sum(1 for i in self.identities if i.mfa_enabled)


@dataclass
class IdentityChange:
    """
    A single detected change between two snapshots for one identity.

    Attributes:
        change_type:     What kind of change this is.
        identity_id:     Provider-assigned identity ID.
        identity_name:   Human-readable identity name.
        provider:        Cloud provider.
        before_value:    The value before the change (or None for new identities).
        after_value:     The value after the change (or None for removed identities).
        risk_weight:     Signed risk contribution (positive = worse security posture).
        note:            Human-readable explanation.
    """
    change_type:   DriftChangeType
    identity_id:   str
    identity_name: str
    provider:      str
    before_value:  Optional[str] = None
    after_value:   Optional[str] = None
    risk_weight:   int           = 0
    note:          str           = ""

    @property
    def is_high_risk(self) -> bool:
        return self.change_type in _HIGH_RISK_TYPES


# ---------------------------------------------------------------------------
# DriftReport
# ---------------------------------------------------------------------------

@dataclass
class DriftReport:
    """
    Result of comparing two IAM snapshots.

    Attributes:
        baseline_label:   Label of the baseline snapshot.
        current_label:    Label of the current snapshot.
        changes:          All detected changes.
        baseline_count:   Number of identities in baseline.
        current_count:    Number of identities in current.
    """
    baseline_label: str
    current_label:  str
    changes:        list[IdentityChange] = field(default_factory=list)
    baseline_count: int                  = 0
    current_count:  int                  = 0

    @property
    def risk_delta(self) -> int:
        """
        Net risk change between snapshots.
        Positive → security posture worsened.
        Negative → security posture improved.
        """
        return sum(c.risk_weight for c in self.changes)

    @property
    def high_risk_changes(self) -> list[IdentityChange]:
        """Changes representing security regressions."""
        return [c for c in self.changes if c.is_high_risk]

    @property
    def positive_changes(self) -> list[IdentityChange]:
        """Changes representing security improvements (risk_weight < 0)."""
        return [c for c in self.changes if c.risk_weight < 0]

    def changes_by_type(self, change_type: DriftChangeType) -> list[IdentityChange]:
        """Return all changes of a specific type."""
        return [c for c in self.changes if c.change_type == change_type]

    def summary(self) -> str:
        """
        Return a human-readable drift summary.

        Example::

            IAM Drift Report: "2026-04-01" → "2026-04-06"
            ──────────────────────────────────────────────
            Baseline identities: 45  |  Current: 47
            Total changes:  8  (3 high-risk)
            Risk delta: +9 (posture WORSENED)
            ──────────────────────────────────────────────
            Change breakdown:
              new_identity:     2
              privilege_gained: 1
              mfa_disabled:     1
              policy_added:     4
        """
        from collections import Counter
        type_counts: Counter = Counter(c.change_type.value for c in self.changes)
        risk_label = "WORSENED" if self.risk_delta > 0 else ("IMPROVED" if self.risk_delta < 0 else "UNCHANGED")
        risk_sign  = "+" if self.risk_delta > 0 else ""

        lines = [
            f'IAM Drift Report: "{self.baseline_label}" \u2192 "{self.current_label}"',
            "\u2500" * 46,
            f"Baseline identities: {self.baseline_count}  |  Current: {self.current_count}",
            f"Total changes: {len(self.changes):>3}  ({len(self.high_risk_changes)} high-risk)",
            f"Risk delta: {risk_sign}{self.risk_delta} (posture {risk_label})",
        ]
        if type_counts:
            lines.append("\u2500" * 46)
            lines.append("Change breakdown:")
            for change_type, count in sorted(type_counts.items()):
                lines.append(f"  {change_type}: {count}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core diff function
# ---------------------------------------------------------------------------

def diff_snapshots(
    baseline: IamSnapshot,
    current:  IamSnapshot,
) -> DriftReport:
    """
    Compare two IAM snapshots and return a DriftReport.

    Args:
        baseline: The earlier snapshot (reference point).
        current:  The later snapshot (current state).

    Returns:
        DriftReport with all detected IdentityChange objects.
    """
    report = DriftReport(
        baseline_label=baseline.label,
        current_label=current.label,
        baseline_count=len(baseline.identities),
        current_count=len(current.identities),
    )

    base_map = baseline.identity_map()
    curr_map = current.identity_map()

    # Detect new identities
    for key, identity in curr_map.items():
        if key not in base_map:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.NEW_IDENTITY,
                identity_id=identity.identity_id,
                identity_name=identity.identity_name,
                provider=identity.provider,
                after_value=identity.identity_type.value,
                risk_weight=_CHANGE_RISK[DriftChangeType.NEW_IDENTITY],
                note=(
                    f"New {'privileged ' if identity.is_privileged else ''}"
                    f"{identity.identity_type.value} identity '{identity.identity_name}' detected."
                ),
            ))

    # Detect removed identities
    for key, identity in base_map.items():
        if key not in curr_map:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.REMOVED_IDENTITY,
                identity_id=identity.identity_id,
                identity_name=identity.identity_name,
                provider=identity.provider,
                before_value=identity.identity_type.value,
                risk_weight=_CHANGE_RISK[DriftChangeType.REMOVED_IDENTITY],
                note=f"Identity '{identity.identity_name}' was removed.",
            ))

    # Detect changes in existing identities
    for key in base_map:
        if key not in curr_map:
            continue   # Already recorded as REMOVED

        base_id = base_map[key]
        curr_id = curr_map[key]

        # Privilege change
        if not base_id.is_privileged and curr_id.is_privileged:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.PRIVILEGE_GAINED,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                before_value="not_privileged",
                after_value="privileged",
                risk_weight=_CHANGE_RISK[DriftChangeType.PRIVILEGE_GAINED],
                note=f"'{curr_id.identity_name}' gained privileged access.",
            ))
        elif base_id.is_privileged and not curr_id.is_privileged:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.PRIVILEGE_LOST,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                before_value="privileged",
                after_value="not_privileged",
                risk_weight=_CHANGE_RISK[DriftChangeType.PRIVILEGE_LOST],
                note=f"'{curr_id.identity_name}' lost privileged access (reduction in permissions).",
            ))

        # MFA change
        if base_id.mfa_enabled and not curr_id.mfa_enabled:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.MFA_DISABLED,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                before_value="mfa_enabled",
                after_value="mfa_disabled",
                risk_weight=_CHANGE_RISK[DriftChangeType.MFA_DISABLED],
                note=f"MFA was disabled for '{curr_id.identity_name}'.",
            ))
        elif not base_id.mfa_enabled and curr_id.mfa_enabled:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.MFA_ENABLED,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                before_value="mfa_disabled",
                after_value="mfa_enabled",
                risk_weight=_CHANGE_RISK[DriftChangeType.MFA_ENABLED],
                note=f"MFA was enabled for '{curr_id.identity_name}'.",
            ))

        # Policy changes
        base_policies = set(base_id.attached_policies)
        curr_policies = set(curr_id.attached_policies)

        added_policies = curr_policies - base_policies
        removed_policies = base_policies - curr_policies

        if added_policies:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.POLICY_ADDED,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                after_value=", ".join(sorted(added_policies)),
                risk_weight=_CHANGE_RISK[DriftChangeType.POLICY_ADDED],
                note=f"New policies attached to '{curr_id.identity_name}': "
                     f"{', '.join(sorted(added_policies))}",
            ))

        if removed_policies:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.POLICY_REMOVED,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                before_value=", ".join(sorted(removed_policies)),
                risk_weight=_CHANGE_RISK[DriftChangeType.POLICY_REMOVED],
                note=f"Policies removed from '{curr_id.identity_name}': "
                     f"{', '.join(sorted(removed_policies))}",
            ))

        # Status change
        if base_id.status != curr_id.status:
            report.changes.append(IdentityChange(
                change_type=DriftChangeType.STATUS_CHANGED,
                identity_id=curr_id.identity_id,
                identity_name=curr_id.identity_name,
                provider=curr_id.provider,
                before_value=base_id.status.value,
                after_value=curr_id.status.value,
                risk_weight=_CHANGE_RISK[DriftChangeType.STATUS_CHANGED],
                note=(
                    f"Status changed for '{curr_id.identity_name}': "
                    f"{base_id.status.value} → {curr_id.status.value}"
                ),
            ))

    return report
