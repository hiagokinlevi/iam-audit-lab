"""Analyze AWS account password policy posture from offline exports or boto3 data."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PasswordPolicyFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    weight: int


@dataclass
class PasswordPolicyResult:
    account_id: str
    findings: list[PasswordPolicyFinding] = field(default_factory=list)
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "risk_score": self.risk_score,
            "findings": [asdict(finding) for finding in self.findings],
        }

    def summary(self) -> str:
        if not self.findings:
            return f"AWS account {self.account_id}: password policy meets the baseline."
        return (
            f"AWS account {self.account_id}: {len(self.findings)} password policy "
            f"finding(s), risk_score={self.risk_score}/100."
        )


_RULES: dict[str, tuple[str, str, int, str]] = {
    "PW-001": (
        "HIGH",
        "AWS account has no custom password policy",
        35,
        "Create an account password policy with length, complexity, and reuse controls.",
    ),
    "PW-002": (
        "HIGH",
        "Minimum password length is below 14 characters",
        25,
        "Set MinimumPasswordLength to at least 14 characters.",
    ),
    "PW-003": (
        "MEDIUM",
        "Password complexity controls are incomplete",
        20,
        "Require uppercase, lowercase, numeric, and symbol characters.",
    ),
    "PW-004": (
        "MEDIUM",
        "Password reuse prevention is below 24 remembered passwords",
        15,
        "Set PasswordReusePrevention to 24 to block reuse of recent passwords.",
    ),
    "PW-005": (
        "LOW",
        "Users cannot change their own passwords",
        10,
        "Allow users to change their own passwords unless a stricter federation flow owns passwords.",
    ),
    "PW-006": (
        "MEDIUM",
        "Password expiration exceeds 90 days or is disabled",
        20,
        "Set ExpirePasswords to true and MaxPasswordAge to 90 days or fewer for local IAM users.",
    ),
}


def analyze_password_policy(
    policy: dict[str, Any] | None,
    account_id: str = "unknown",
) -> PasswordPolicyResult:
    """Evaluate an AWS account password policy against the project baseline."""
    findings: list[PasswordPolicyFinding] = []

    if not policy:
        findings.append(_finding("PW-001", "GetAccountPasswordPolicy returned no policy."))
        return _result(account_id, findings)

    minimum_length = _int(policy.get("MinimumPasswordLength"), 0)
    if minimum_length < 14:
        findings.append(
            _finding(
                "PW-002",
                f"MinimumPasswordLength is {minimum_length}; expected at least 14.",
            )
        )

    missing_complexity = [
        label
        for label, key in [
            ("uppercase", "RequireUppercaseCharacters"),
            ("lowercase", "RequireLowercaseCharacters"),
            ("numbers", "RequireNumbers"),
            ("symbols", "RequireSymbols"),
        ]
        if not bool(policy.get(key))
    ]
    if missing_complexity:
        findings.append(
            _finding(
                "PW-003",
                "Missing complexity requirements: " + ", ".join(missing_complexity) + ".",
            )
        )

    reuse_prevention = _int(policy.get("PasswordReusePrevention"), 0)
    if reuse_prevention < 24:
        findings.append(
            _finding(
                "PW-004",
                f"PasswordReusePrevention is {reuse_prevention}; expected at least 24.",
            )
        )

    expire_passwords = bool(policy.get("ExpirePasswords"))
    max_password_age = _int(policy.get("MaxPasswordAge"), 0)
    if not expire_passwords or max_password_age == 0 or max_password_age > 90:
        if not expire_passwords:
            detail = "ExpirePasswords is false, so IAM console passwords never expire."
        elif max_password_age > 90:
            detail = f"MaxPasswordAge is {max_password_age}; expected 90 days or fewer."
        else:
            detail = "MaxPasswordAge is not set to a positive value, so password expiration is ineffective."
        findings.append(_finding("PW-006", detail))

    if policy.get("AllowUsersToChangePassword") is False:
        findings.append(
            _finding(
                "PW-005",
                "AllowUsersToChangePassword is false, which can increase helpdesk reset risk.",
            )
        )

    return _result(account_id, findings)


def _finding(rule_id: str, detail: str) -> PasswordPolicyFinding:
    severity, title, weight, remediation = _RULES[rule_id]
    return PasswordPolicyFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        remediation=remediation,
        weight=weight,
    )


def _result(account_id: str, findings: list[PasswordPolicyFinding]) -> PasswordPolicyResult:
    fired = {finding.rule_id for finding in findings}
    risk_score = min(100, sum(_RULES[rule_id][2] for rule_id in fired))
    return PasswordPolicyResult(account_id=account_id, findings=findings, risk_score=risk_score)


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
