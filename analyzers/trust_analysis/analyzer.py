"""
IAM Trust Analysis
===================
Analyzes IAM role trust policies to detect over-permissive cross-account
and external trust relationships.

Trust policy vulnerabilities allow privilege escalation via role assumption:
  - A role trusted by "AWS": "*" can be assumed by any AWS account
  - A role trusted by an external service without condition keys is an attack
    vector if the service is ever compromised
  - Wildcard conditions (StringLike with *) reduce the benefit of trust boundaries

Currently supports AWS IAM role trust policies (JSON AssumeRolePolicyDocument).

Checks performed:
  - TRP001 CRITICAL: Trust policy trusts all AWS principals (*) — anyone can assume
  - TRP002 HIGH:     Trust policy trusts an anonymous/public principal
  - TRP003 HIGH:     Cross-account trust without external ID condition (confused deputy)
  - TRP004 MEDIUM:   Wildcard condition in trust policy (overly broad condition)
  - TRP005 LOW:      Trust to a third-party service without sts:ExternalId condition
  - TRP006 INFO:     Cross-account trust (expected, but document for review)

Usage:
    from analyzers.trust_analysis.analyzer import analyze_trust_policies, TrustPolicyRecord

    record = TrustPolicyRecord(
        role_arn="arn:aws:iam::123456789012:role/MyRole",
        role_name="MyRole",
        trust_policy=role["AssumeRolePolicyDocument"],
        account_id="123456789012",
    )
    findings = analyze_trust_policies([record])
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Input type
# ---------------------------------------------------------------------------

@dataclass
class TrustPolicyRecord:
    """A single IAM role's trust policy for analysis."""

    role_arn: str
    role_name: str
    trust_policy: dict[str, Any]  # Parsed AssumeRolePolicyDocument
    account_id: str               # The account ID this role belongs to
    tags: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Finding type
# ---------------------------------------------------------------------------

@dataclass
class TrustFinding:
    """A trust policy security finding."""

    rule_id: str
    severity: str        # "critical", "high", "medium", "low", "info"
    role_arn: str
    role_name: str
    title: str
    detail: str          # Specific principal or condition that triggered the finding
    remediation: str


# ---------------------------------------------------------------------------
# Known third-party service principal prefixes
# ---------------------------------------------------------------------------

# AWS services that legitimately assume roles but may need ExternalId checks
_THIRD_PARTY_SERVICE_DOMAINS = {
    "datadog.com", "newrelic.com", "cloudhealth.com", "turbot.com",
    "sumo-logic.com", "lacework.com", "snyk.io", "tenable.com",
}

_AWS_ACCOUNT_ARN_RE = re.compile(r"arn:aws:iam::(\d{12}):root")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_trust_policies(
    records: list[TrustPolicyRecord],
) -> list[TrustFinding]:
    """
    Analyze IAM role trust policies for over-permissive conditions.

    Args:
        records: List of TrustPolicyRecord objects (one per IAM role).

    Returns:
        List of TrustFinding objects sorted by severity (critical first).
    """
    all_findings: list[TrustFinding] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for record in records:
        findings = _check_trust_policy(record)
        all_findings.extend(findings)

    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return all_findings


def _check_trust_policy(record: TrustPolicyRecord) -> list[TrustFinding]:
    """Run all trust policy checks against a single role."""
    findings: list[TrustFinding] = []
    statements = record.trust_policy.get("Statement", [])

    for stmt in statements:
        effect = stmt.get("Effect", "Deny")
        if effect.lower() != "allow":
            continue  # Only analyze Allow statements

        principal = stmt.get("Principal", {})
        condition = stmt.get("Condition", {})

        _check_wildcard_principal(record, principal, condition, findings)
        _check_cross_account(record, principal, condition, findings)
        _check_wildcard_conditions(record, principal, condition, findings)
        _check_third_party_no_external_id(record, principal, condition, findings)

    return findings


def _principal_values(principal: Any) -> list[str]:
    """Flatten a Principal value to a list of strings."""
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        values: list[str] = []
        for v in principal.values():
            if isinstance(v, str):
                values.append(v)
            elif isinstance(v, list):
                values.extend(v)
        return values
    return []


def _check_wildcard_principal(
    record: TrustPolicyRecord,
    principal: Any,
    condition: dict,
    findings: list[TrustFinding],
) -> None:
    """TRP001/TRP002: Wildcard or anonymous principal."""
    values = _principal_values(principal)

    if "*" in values:
        findings.append(TrustFinding(
            rule_id="TRP001",
            severity="critical",
            role_arn=record.role_arn,
            role_name=record.role_name,
            title=f"Trust policy allows any AWS principal (*) to assume role '{record.role_name}'",
            detail='Principal: "*"',
            remediation=(
                "Replace the wildcard principal with the specific AWS account ARNs, "
                "IAM user ARNs, or service principals that should be allowed to assume this role. "
                "A wildcard trust policy means any authenticated AWS account can assume the role."
            ),
        ))

    # Public/anonymous access
    if "anonymous" in [v.lower() for v in values]:
        findings.append(TrustFinding(
            rule_id="TRP002",
            severity="critical",
            role_arn=record.role_arn,
            role_name=record.role_name,
            title=f"Trust policy grants anonymous/public access to role '{record.role_name}'",
            detail=f"Principal contains anonymous access indicator",
            remediation=(
                "Remove anonymous principals from the trust policy immediately. "
                "No IAM role should be assumable by unauthenticated principals."
            ),
        ))


def _check_cross_account(
    record: TrustPolicyRecord,
    principal: Any,
    condition: dict,
    findings: list[TrustFinding],
) -> None:
    """TRP003/TRP006: Cross-account trust."""
    values = _principal_values(principal)

    for value in values:
        match = _AWS_ACCOUNT_ARN_RE.match(value)
        if match:
            trusted_account = match.group(1)
            if trusted_account != record.account_id:
                # Cross-account trust — check for ExternalId condition
                has_external_id = "sts:ExternalId" in condition.get("StringEquals", {})

                if not has_external_id:
                    findings.append(TrustFinding(
                        rule_id="TRP003",
                        severity="high",
                        role_arn=record.role_arn,
                        role_name=record.role_name,
                        title=(
                            f"Cross-account trust to account {trusted_account} without "
                            "sts:ExternalId condition (confused deputy risk)"
                        ),
                        detail=f"Trusted principal: {value}",
                        remediation=(
                            f"Add an sts:ExternalId condition to the trust policy. "
                            "The ExternalId prevents confused deputy attacks where a third party "
                            "could trick your service into assuming this role on behalf of an "
                            "attacker. Coordinate the ExternalId value with account {trusted_account}."
                        ),
                    ))
                else:
                    # Cross-account with ExternalId — flag as INFO for documentation
                    findings.append(TrustFinding(
                        rule_id="TRP006",
                        severity="info",
                        role_arn=record.role_arn,
                        role_name=record.role_name,
                        title=f"Cross-account trust to account {trusted_account} (with ExternalId)",
                        detail=f"Trusted principal: {value} — has ExternalId condition",
                        remediation=(
                            "Cross-account trust with ExternalId is acceptable. "
                            "Review periodically to ensure the trusted account still requires access."
                        ),
                    ))


def _check_wildcard_conditions(
    record: TrustPolicyRecord,
    principal: Any,
    condition: dict,
    findings: list[TrustFinding],
) -> None:
    """TRP004: Wildcard pattern in condition values."""
    for operator, conditions in condition.items():
        if not isinstance(conditions, dict):
            continue
        for key, value in conditions.items():
            values = value if isinstance(value, list) else [value]
            for v in values:
                if isinstance(v, str) and "*" in v and len(v) > 1:
                    findings.append(TrustFinding(
                        rule_id="TRP004",
                        severity="medium",
                        role_arn=record.role_arn,
                        role_name=record.role_name,
                        title=(
                            f"Wildcard condition in trust policy for role '{record.role_name}'"
                        ),
                        detail=f"Condition: {operator}:{key} = '{v}'",
                        remediation=(
                            "Replace wildcard conditions with exact values where possible. "
                            "Wildcards in trust conditions reduce the security benefit of the "
                            "trust boundary. For example, replace 'arn:aws:iam::*:root' with "
                            "the specific account ARN."
                        ),
                    ))


def _check_third_party_no_external_id(
    record: TrustPolicyRecord,
    principal: Any,
    condition: dict,
    findings: list[TrustFinding],
) -> None:
    """TRP005: Known third-party service without ExternalId."""
    values = _principal_values(principal)
    has_external_id = "sts:ExternalId" in condition.get("StringEquals", {})

    for value in values:
        for domain in _THIRD_PARTY_SERVICE_DOMAINS:
            if domain in value.lower() and not has_external_id:
                findings.append(TrustFinding(
                    rule_id="TRP005",
                    severity="low",
                    role_arn=record.role_arn,
                    role_name=record.role_name,
                    title=(
                        f"Third-party service principal from '{domain}' without sts:ExternalId"
                    ),
                    detail=f"Principal: {value}",
                    remediation=(
                        f"Add a sts:ExternalId condition when trusting third-party services. "
                        "Verify with the provider ({domain}) what ExternalId value they require. "
                        "This prevents confused deputy attacks if the provider is compromised."
                    ),
                ))
