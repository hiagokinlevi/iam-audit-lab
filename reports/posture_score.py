"""
IAM Posture Score
==================
Computes an overall IAM security posture score (0–100) from a collection
of audit findings.

Scoring model:
  Each finding category deducts points from 100 based on severity:
    - CRITICAL finding: -25 points (capped per category)
    - HIGH finding:     -10 points
    - MEDIUM finding:   -5 points
    - LOW finding:      -2 points
    - INFORMATIONAL:    -0 points

  The score floor is 0 (cannot go negative).

  Additionally, positive contributions are applied for security controls
  that ARE in place (e.g. high MFA coverage, no excessive admin policies).

Score ranges:
  90–100: Excellent — very low risk, minor findings only
  75–89:  Good — well-controlled, some gaps to address
  50–74:  Fair — significant findings requiring remediation
  25–49:  Poor — critical or multiple high-severity gaps
  0–24:   Critical — immediate action required

Usage:
    from reports.posture_score import compute_posture_score, PostureScore

    score = compute_posture_score(findings, mfa_coverage_percent=85.0)
    print(f"IAM Posture: {score.score}/100 ({score.rating})")
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from schemas.identity import AuditFinding, FindingCategory, FindingSeverity


# ---------------------------------------------------------------------------
# Deduction weights per severity
# ---------------------------------------------------------------------------

_DEDUCTIONS: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 25,
    FindingSeverity.HIGH: 10,
    FindingSeverity.MEDIUM: 5,
    FindingSeverity.LOW: 2,
    FindingSeverity.INFORMATIONAL: 0,
}

# Maximum total deduction per finding category to prevent over-penalizing
# for the same type of issue repeated many times
_MAX_DEDUCTION_PER_CATEGORY: dict[FindingCategory, int] = {
    FindingCategory.EXCESSIVE_PERMISSIONS: 30,
    FindingCategory.PRIVILEGED_WITHOUT_MFA: 40,
    FindingCategory.MFA_NOT_ENABLED: 20,
    FindingCategory.INACTIVE_ACCOUNT: 10,
}

# Default max deduction per category if not listed above
_DEFAULT_MAX_PER_CATEGORY = 20


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class PostureScore:
    """IAM posture score with breakdown by category."""

    score: int                           # 0–100 overall score
    findings_count: int
    deductions_by_category: dict[str, int]  # category → total deductions
    mfa_coverage_percent: Optional[float]
    bonus_points: int                    # Points added for positive controls
    notes: list[str] = field(default_factory=list)

    @property
    def rating(self) -> str:
        if self.score >= 90:
            return "Excellent"
        if self.score >= 75:
            return "Good"
        if self.score >= 50:
            return "Fair"
        if self.score >= 25:
            return "Poor"
        return "Critical"

    @property
    def color(self) -> str:
        """ANSI color for terminal output."""
        if self.score >= 90:
            return "green"
        if self.score >= 75:
            return "yellow"
        return "red"


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def compute_posture_score(
    findings: list[AuditFinding],
    mfa_coverage_percent: Optional[float] = None,
    has_privileged_accounts_with_mfa: bool = True,
) -> PostureScore:
    """
    Compute an IAM posture score from a list of audit findings.

    Args:
        findings:                       All AuditFinding objects from all analyzers.
        mfa_coverage_percent:           Percentage of human accounts with MFA enabled.
                                        If provided, contributes a bonus for high coverage.
        has_privileged_accounts_with_mfa: If True, all privileged accounts have MFA enabled.
                                          Adds a bonus to the score.

    Returns:
        PostureScore with score, rating, and breakdown.
    """
    total_deductions = 0
    deductions_by_category: dict[str, int] = {}
    notes: list[str] = []

    # Group findings by category for capped deductions
    from collections import defaultdict
    by_category: dict[FindingCategory, list[AuditFinding]] = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)

    for category, category_findings in by_category.items():
        category_deductions = 0
        max_deduction = _MAX_DEDUCTION_PER_CATEGORY.get(category, _DEFAULT_MAX_PER_CATEGORY)

        for finding in category_findings:
            deduction = _DEDUCTIONS.get(finding.severity, 0)
            category_deductions = min(category_deductions + deduction, max_deduction)

        total_deductions += category_deductions
        if category_deductions > 0:
            deductions_by_category[category.value] = category_deductions

    # Bonus points for positive security posture
    bonus_points = 0

    if mfa_coverage_percent is not None:
        if mfa_coverage_percent >= 99.0:
            bonus_points += 5
            notes.append("Bonus +5: Near-complete MFA coverage (≥99%)")
        elif mfa_coverage_percent >= 90.0:
            bonus_points += 3
            notes.append("Bonus +3: High MFA coverage (≥90%)")
        elif mfa_coverage_percent < 50.0:
            notes.append("Warning: MFA coverage below 50% — consider mandatory enrollment")

    if has_privileged_accounts_with_mfa:
        bonus_points += 5
        notes.append("Bonus +5: All privileged accounts have MFA enabled")

    # Compute final score
    score = max(0, min(100 + bonus_points - total_deductions, 100))

    return PostureScore(
        score=score,
        findings_count=len(findings),
        deductions_by_category=deductions_by_category,
        mfa_coverage_percent=mfa_coverage_percent,
        bonus_points=bonus_points,
        notes=notes,
    )


def format_score_report(score: PostureScore) -> str:
    """Format the posture score as a human-readable multi-line string."""
    lines = [
        f"IAM Posture Score: {score.score}/100 ({score.rating})",
        f"Findings:          {score.findings_count}",
        f"MFA coverage:      {score.mfa_coverage_percent:.1f}%" if score.mfa_coverage_percent is not None else "MFA coverage:      n/a",
    ]

    if score.deductions_by_category:
        lines.append("\nDeductions:")
        for cat, pts in sorted(score.deductions_by_category.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat:<35} -{pts}")

    if score.bonus_points > 0:
        lines.append(f"\nBonus:             +{score.bonus_points}")

    if score.notes:
        lines.append("\nNotes:")
        for note in score.notes:
            lines.append(f"  {note}")

    return "\n".join(lines)
