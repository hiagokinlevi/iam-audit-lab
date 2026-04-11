"""
Excessive Permissions Analyzer
================================
Detects IAM identities with overly broad or privileged permission assignments.

Analysis approach:
  The analyzer uses a heuristic allow-list of known highly-privileged policy
  and role names. If an identity has any of these attached, it is flagged.
  This approach produces reliable results for well-known permission sets but
  will miss custom roles with broad permissions (addressed in v0.2).

Limitations:
  - Does not analyze custom inline policies (AWS) or custom roles (GCP/Azure)
  - Does not account for permission boundaries (AWS) or SCPs (AWS Organizations)
  - Role assignments at management group level (Azure) are not collected in v0.1
"""

from __future__ import annotations

from schemas.identity import AuditFinding, FindingCategory, FindingSeverity, IdentityRecord

# ---------------------------------------------------------------------------
# Permission dictionaries by provider
# ---------------------------------------------------------------------------

# AWS policies that confer excessive permissions.
# Severity is assigned based on the blast radius of the policy.
_AWS_EXCESSIVE_POLICIES: dict[str, tuple[FindingSeverity, str]] = {
    "AdministratorAccess": (
        FindingSeverity.CRITICAL,
        "Full administrative access to all AWS services and resources.",
    ),
    "PowerUserAccess": (
        FindingSeverity.HIGH,
        "Administrative access to all services except IAM management.",
    ),
    "IAMFullAccess": (
        FindingSeverity.HIGH,
        "Full control over IAM — can create admin users and escalate privileges.",
    ),
    "AWSOrganizationsFullAccess": (
        FindingSeverity.CRITICAL,
        "Full control over AWS Organizations — can affect all accounts in the organization.",
    ),
    "AmazonS3FullAccess": (
        FindingSeverity.MEDIUM,
        "Unrestricted read/write access to all S3 buckets in the account.",
    ),
    "AmazonEC2FullAccess": (
        FindingSeverity.MEDIUM,
        "Unrestricted access to all EC2 resources.",
    ),
    "AWSLambdaFullAccess": (
        FindingSeverity.MEDIUM,
        "Unrestricted access to all Lambda functions.",
    ),
}

# Azure role definitions that confer excessive permissions.
_AZURE_EXCESSIVE_ROLES: dict[str, tuple[FindingSeverity, str]] = {
    "Owner": (
        FindingSeverity.CRITICAL,
        "Full access to all Azure resources including the ability to assign roles.",
    ),
    "Contributor": (
        FindingSeverity.HIGH,
        "Full access to create and manage all Azure resources. Cannot assign roles.",
    ),
    "User Access Administrator": (
        FindingSeverity.HIGH,
        "Can manage user access to all Azure resources.",
    ),
    "Security Admin": (
        FindingSeverity.MEDIUM,
        "Can view security policies and update security settings.",
    ),
}

# GCP roles that confer excessive permissions.
_GCP_EXCESSIVE_ROLES: dict[str, tuple[FindingSeverity, str]] = {
    "roles/owner": (
        FindingSeverity.CRITICAL,
        "Full access to all GCP resources in the project.",
    ),
    "roles/editor": (
        FindingSeverity.HIGH,
        "Read and write access to all GCP resources.",
    ),
    "roles/iam.serviceAccountAdmin": (
        FindingSeverity.HIGH,
        "Can create and manage service accounts — potential for privilege escalation.",
    ),
    "roles/resourcemanager.projectIamAdmin": (
        FindingSeverity.HIGH,
        "Can modify project IAM policies — potential for privilege escalation.",
    ),
    "roles/compute.admin": (
        FindingSeverity.MEDIUM,
        "Full control over Compute Engine resources.",
    ),
}

# Map providers to their excessive policy dictionaries
_POLICY_DICT_BY_PROVIDER: dict[str, dict[str, tuple[FindingSeverity, str]]] = {
    "aws": _AWS_EXCESSIVE_POLICIES,
    "azure": _AZURE_EXCESSIVE_ROLES,
    "gcp": _GCP_EXCESSIVE_ROLES,
}

_GCP_PUBLIC_PRINCIPALS = frozenset({"allusers", "allauthenticatedusers"})

_RISK_MAP: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 1.0,
    FindingSeverity.HIGH: 0.75,
    FindingSeverity.MEDIUM: 0.5,
    FindingSeverity.LOW: 0.25,
    FindingSeverity.INFORMATIONAL: 0.1,
}


def _is_gcp_public_member(identity: IdentityRecord) -> bool:
    """Return True when the record represents a public GCP IAM member."""
    return (
        identity.provider == "gcp"
        and identity.identity_name.lower() in _GCP_PUBLIC_PRINCIPALS
    )


def _gcp_public_binding_severity(role_name: str) -> FindingSeverity:
    """Assign severity for a public GCP IAM binding based on the granted role."""
    normalized_role = role_name.lower()

    if normalized_role == "roles/owner":
        return FindingSeverity.CRITICAL
    if role_name in _GCP_EXCESSIVE_ROLES or "admin" in normalized_role or normalized_role.endswith(
        "editor"
    ):
        return FindingSeverity.HIGH
    return FindingSeverity.MEDIUM


def _build_gcp_public_binding_finding(
    identity: IdentityRecord,
    role_name: str,
) -> AuditFinding:
    """Build a finding for a public GCP IAM member binding."""
    severity = _gcp_public_binding_severity(role_name)
    principal = identity.identity_name
    audience = (
        "any internet user"
        if principal == "allUsers"
        else "any Google-authenticated principal"
    )

    return AuditFinding(
        category=FindingCategory.EXCESSIVE_PERMISSIONS,
        severity=severity,
        provider=identity.provider,
        identity_id=identity.identity_id,
        identity_name=identity.identity_name,
        title=f"Public GCP IAM binding: {principal} -> {role_name}",
        description=(
            f"GCP IAM member '{principal}' grants project access to {audience}. "
            f"The bound role '{role_name}' should be restricted to named identities or groups."
        ),
        evidence=[
            f"Public member '{principal}' appears in the GCP IAM policy",
            f"Granted role: '{role_name}'",
            "Public principals should not receive project-level IAM roles",
        ],
        remediation=(
            f"Remove '{principal}' from the IAM binding for '{role_name}' and replace it with "
            "specific users, groups, or service accounts. If broad public access is required "
            "for a workload, use service-specific controls instead of project-level IAM."
        ),
        risk_score=_RISK_MAP.get(severity, 0.5),
    )


def analyze_excessive_permissions(
    identities: list[IdentityRecord],
) -> list[AuditFinding]:
    """
    Analyze a list of IAM identities for excessive permission assignments.

    For each identity, checks attached_policies against the provider's list
    of known over-privileged policies and roles. Produces an AuditFinding
    for each match.

    Args:
        identities: List of collected IdentityRecord objects.

    Returns:
        List of AuditFinding objects, one per (identity, excessive_policy) pair.
    """
    findings: list[AuditFinding] = []

    for identity in identities:
        provider_policies = _POLICY_DICT_BY_PROVIDER.get(identity.provider, {})

        for policy_name in identity.attached_policies:
            if _is_gcp_public_member(identity):
                findings.append(_build_gcp_public_binding_finding(identity, policy_name))
                continue

            if policy_name in provider_policies:
                severity, description = provider_policies[policy_name]

                finding = AuditFinding(
                    category=FindingCategory.EXCESSIVE_PERMISSIONS,
                    severity=severity,
                    provider=identity.provider,
                    identity_id=identity.identity_id,
                    identity_name=identity.identity_name,
                    title=f"Excessive policy attached: {policy_name}",
                    description=description,
                    evidence=[
                        (
                            f"Policy '{policy_name}' is directly attached to "
                            f"'{identity.identity_name}'"
                        ),
                        f"Identity type: {identity.identity_type.value}",
                    ],
                    remediation=(
                        f"Review whether '{identity.identity_name}' requires '{policy_name}'. "
                        "Replace with a least-privilege policy that grants only the permissions "
                        "actually needed. For service accounts, prefer purpose-built policies "
                        "over managed admin policies."
                    ),
                    risk_score=_RISK_MAP.get(severity, 0.5),
                )
                findings.append(finding)

    return findings
