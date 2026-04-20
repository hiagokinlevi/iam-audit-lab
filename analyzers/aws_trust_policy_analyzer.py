from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TrustPolicyFinding:
    role_name: str
    severity: str
    issue: str
    principal: str
    details: str


_ALLOWED_SERVICE_PRINCIPALS = {
    "ec2.amazonaws.com",
    "lambda.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "eks.amazonaws.com",
    "states.amazonaws.com",
    "ssm.amazonaws.com",
    "events.amazonaws.com",
    "cloudformation.amazonaws.com",
}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_account_id_from_arn(arn: str) -> str | None:
    # Example: arn:aws:iam::123456789012:role/MyRole
    parts = arn.split(":")
    if len(parts) < 6:
        return None
    account_id = parts[4]
    if account_id.isdigit() and len(account_id) == 12:
        return account_id
    return None


def _iter_principals(principal: Any) -> list[tuple[str, str]]:
    """Return (principal_type, principal_value) pairs."""
    out: list[tuple[str, str]] = []

    if principal == "*":
        return [("Any", "*")]

    if not isinstance(principal, dict):
        return out

    for p_type, p_val in principal.items():
        for item in _as_list(p_val):
            if isinstance(item, str):
                out.append((p_type, item))
    return out


def analyze_trust_policies(
    roles: list[dict[str, Any]],
    account_id: str,
    allowed_external_accounts: set[str] | None = None,
) -> list[TrustPolicyFinding]:
    """
    Analyze AWS IAM role trust policies for risky cross-account trust.

    Expected role shape:
      {
        "RoleName": "...",
        "AssumeRolePolicyDocument": { ... IAM trust policy ... }
      }
    """
    allowed_external_accounts = allowed_external_accounts or set()
    findings: list[TrustPolicyFinding] = []

    for role in roles:
        role_name = role.get("RoleName", "<unknown-role>")
        policy = role.get("AssumeRolePolicyDocument") or {}
        statements = _as_list(policy.get("Statement"))

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            effect = statement.get("Effect", "")
            if effect != "Allow":
                continue

            for p_type, p_value in _iter_principals(statement.get("Principal")):
                # Wildcard principal
                if p_value == "*":
                    findings.append(
                        TrustPolicyFinding(
                            role_name=role_name,
                            severity="high",
                            issue="wildcard_trust_principal",
                            principal="*",
                            details="Role trust policy allows assumption by any principal.",
                        )
                    )
                    continue

                # AWS account/ARN principals
                if p_type == "AWS":
                    if p_value.isdigit() and len(p_value) == 12:
                        principal_account = p_value
                    else:
                        principal_account = _extract_account_id_from_arn(p_value)

                    if principal_account and principal_account != account_id:
                        sev = "medium" if principal_account in allowed_external_accounts else "high"
                        issue = (
                            "cross_account_trust_allowedlist"
                            if principal_account in allowed_external_accounts
                            else "cross_account_trust"
                        )
                        findings.append(
                            TrustPolicyFinding(
                                role_name=role_name,
                                severity=sev,
                                issue=issue,
                                principal=p_value,
                                details=f"Trusts external account {principal_account}.",
                            )
                        )

                # Federated principals are sensitive by default
                if p_type == "Federated":
                    findings.append(
                        TrustPolicyFinding(
                            role_name=role_name,
                            severity="medium",
                            issue="federated_trust",
                            principal=p_value,
                            details="Role trust policy allows federated principal; validate audience/conditions.",
                        )
                    )

                # Service principals outside common set (heuristic)
                if p_type == "Service" and p_value not in _ALLOWED_SERVICE_PRINCIPALS:
                    findings.append(
                        TrustPolicyFinding(
                            role_name=role_name,
                            severity="low",
                            issue="uncommon_service_principal",
                            principal=p_value,
                            details="Service principal is uncommon; verify this trust relationship is expected.",
                        )
                    )

            # Optional guardrail: missing condition on broad principals
            condition = statement.get("Condition")
            if not condition and statement.get("Principal") in ("*", {"AWS": "*"}):
                findings.append(
                    TrustPolicyFinding(
                        role_name=role_name,
                        severity="high",
                        issue="unconditional_broad_trust",
                        principal="*",
                        details="Broad trust principal is allowed without conditions.",
                    )
                )

    return findings
