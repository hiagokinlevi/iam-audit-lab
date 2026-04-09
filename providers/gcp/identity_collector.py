"""
GCP IAM Identity Collector
============================
Collects IAM members and service accounts from a GCP project.

Uses read-only Cloud IAM API calls. Requires the following permissions:
  - iam.serviceAccounts.list (to list service accounts)
  - resourcemanager.projects.getIamPolicy (to read project IAM policy)
  - iam.roles.list (to list custom roles)

Authentication uses Application Default Credentials (ADC):
  - Set GOOGLE_APPLICATION_CREDENTIALS to a service account key file path, OR
  - Run `gcloud auth application-default login` for local development.

Authorization note: Only use on GCP projects you own or are authorized to audit.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from schemas.identity import IdentityRecord, IdentityStatus, IdentityType

logger = logging.getLogger(__name__)

# GCP role bindings that indicate privileged access
_PRIVILEGED_GCP_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/compute.admin",
    "roles/container.admin",
}


def _get_iam_client() -> Any:
    """
    Create an authenticated GCP IAM client using google-cloud-iam.

    Requires google-cloud-iam to be installed.
    """
    try:
        from google.cloud import iam_admin_v1
        return iam_admin_v1.IAMClient()
    except ImportError:
        raise ImportError(
            "google-cloud-iam is required for GCP collection. "
            "Install it with: pip install google-cloud-iam"
        )


def _get_resource_manager_client() -> Any:
    """Create an authenticated GCP Resource Manager client."""
    try:
        from google.cloud import resourcemanager_v3
        return resourcemanager_v3.ProjectsClient()
    except ImportError:
        raise ImportError(
            "google-cloud-resource-manager is required for GCP policy collection. "
            "Install it with: pip install google-cloud-resource-manager"
        )


def collect_service_accounts(project_id: str) -> list[IdentityRecord]:
    """
    Collect all service accounts in a GCP project.

    Service accounts are the primary non-human identity type in GCP.
    Human users are managed at the Google Workspace / Cloud Identity level
    and are accessed via the Admin SDK (not covered in v0.1).

    Args:
        project_id: GCP project ID (e.g., 'my-project-123').

    Returns:
        List of IdentityRecord, one per service account.
    """
    try:
        client = _get_iam_client()
    except ImportError as e:
        logger.error("Cannot collect GCP service accounts: %s", str(e))
        return []

    service_accounts: list[IdentityRecord] = []

    try:
        from google.cloud import iam_admin_v1
        request = iam_admin_v1.ListServiceAccountsRequest(
            name=f"projects/{project_id}",
        )

        for sa in client.list_service_accounts(request=request):
            # Disabled service accounts are still listed but flagged
            status = IdentityStatus.DISABLED if sa.disabled else IdentityStatus.ACTIVE

            record = IdentityRecord(
                identity_id=sa.unique_id,
                identity_name=sa.email,
                identity_type=IdentityType.SERVICE,
                provider="gcp",
                status=status,
                created_at=None,     # Not available directly via list_service_accounts
                last_activity_at=None,  # Would require Cloud Audit Logs (out of scope v0.1)
                mfa_enabled=False,   # Service accounts authenticate with keys/tokens, not MFA
                arn=sa.email,        # In GCP, the email address is the unique identifier
                raw_metadata={
                    "displayName": sa.display_name,
                    "projectId": sa.project_id,
                    "description": sa.description,
                },
            )
            service_accounts.append(record)

    except Exception as e:
        logger.error("Error collecting GCP service accounts for project %s: %s", project_id, str(e))

    logger.info(
        "Collected %d service accounts from GCP project %s", len(service_accounts), project_id
    )
    return service_accounts


def collect_iam_policy_members(project_id: str) -> list[IdentityRecord]:
    """
    Collect IAM policy members from a GCP project's IAM policy.

    This retrieves all members (users, groups, service accounts) that appear
    in the project's IAM policy bindings, along with their role assignments.
    Unlike collect_service_accounts(), this includes human users bound to
    roles at the project level.

    Args:
        project_id: GCP project ID.

    Returns:
        List of IdentityRecord, one per unique member principal.
    """
    try:
        from google.cloud import resourcemanager_v3, iam_v1
        rm_client = resourcemanager_v3.ProjectsClient()
    except ImportError as e:
        logger.error("Cannot collect GCP IAM policy: %s", str(e))
        return []

    members: dict[str, IdentityRecord] = {}  # Keyed by member string to deduplicate

    try:
        from google.iam.v1 import iam_policy_pb2
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}",
        )
        policy = rm_client.get_iam_policy(request=request)

        for binding in policy.bindings:
            role = binding.role
            is_privileged = role in _PRIVILEGED_GCP_ROLES

            for member in binding.members:
                # GCP member strings have the format: type:identifier
                # e.g., user:alice@example.com, serviceAccount:sa@project.iam.gserviceaccount.com
                if ":" in member:
                    member_type_str, member_id = member.split(":", 1)
                else:
                    member_type_str, member_id = "unknown", member

                # Classify the member type
                if member_type_str == "user":
                    identity_type = IdentityType.HUMAN
                elif member_type_str in ("serviceAccount",):
                    identity_type = IdentityType.SERVICE
                elif member_type_str == "group":
                    identity_type = IdentityType.GROUP
                else:
                    identity_type = IdentityType.UNKNOWN

                if member not in members:
                    # First time seeing this member — create the record
                    members[member] = IdentityRecord(
                        identity_id=member,
                        identity_name=member_id,
                        identity_type=identity_type,
                        provider="gcp",
                        status=IdentityStatus.UNKNOWN,
                        attached_policies=[role],
                        is_privileged=is_privileged,
                        arn=member,
                    )
                else:
                    # Already seen — append this role
                    existing = members[member]
                    existing.attached_policies.append(role)
                    if is_privileged:
                        existing.is_privileged = True

    except Exception as e:
        logger.error(
            "Error reading IAM policy for GCP project %s: %s", project_id, str(e)
        )

    result = list(members.values())
    logger.info(
        "Collected %d unique IAM members from GCP project %s IAM policy",
        len(result),
        project_id,
    )
    return result


def collect_all_identities(project_id: str) -> list[IdentityRecord]:
    """
    Collect all identities from a GCP project.

    Combines service accounts and IAM policy members, deduplicating by
    identity_id to avoid double-counting service accounts that appear in both.
    """
    service_accounts = collect_service_accounts(project_id)
    policy_members = collect_iam_policy_members(project_id)

    # Merge: service accounts from list_service_accounts take precedence
    # (they have more metadata) over entries from the IAM policy
    seen_ids = {sa.identity_id for sa in service_accounts}
    for member in policy_members:
        if member.identity_id not in seen_ids:
            service_accounts.append(member)
            seen_ids.add(member.identity_id)

    return service_accounts
