"""
AWS IAM Identity Collector
===========================
Collects IAM users, groups, roles, and service accounts from AWS.

Uses read-only IAM APIs (iam:List*, iam:Get*).
Requires AWS credentials with the following permissions:
  - iam:ListUsers
  - iam:ListGroups
  - iam:ListRoles
  - iam:GetAccountPasswordPolicy
  - iam:GetAccountSummary
  - iam:GenerateCredentialReport

Authorization note: Only use on AWS accounts you own or are authorized to audit.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from schemas.identity import IdentityRecord, IdentityStatus, IdentityType

logger = logging.getLogger(__name__)

# Policies that indicate an identity has admin-level access.
# This is a heuristic — it does not account for permission boundaries or
# SCPs that may restrict the effective permissions of these policies.
_PRIVILEGED_POLICY_NAMES = {
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess",
    "SecurityAudit",              # Included because auditors can read sensitive configs
    "ReadOnlyAccess",             # Excluded from "privileged" label in most contexts
}
_ADMIN_POLICY_NAMES = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}


def collect_iam_users(session: boto3.Session) -> list[IdentityRecord]:
    """
    Collect all IAM users from the AWS account.

    Includes MFA status and directly attached policies for each user.
    Returns a list of normalized IdentityRecord objects.

    Args:
        session: Authenticated boto3 Session. Use a session configured with
                 read-only IAM permissions.

    Returns:
        List of IdentityRecord, one per IAM user.
    """
    iam = session.client("iam")
    users: list[IdentityRecord] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            # --- MFA device check ---
            try:
                mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
                mfa_enabled = len(mfa_devices["MFADevices"]) > 0
            except ClientError as e:
                # Log the error but continue — a missing MFA response should not
                # halt the entire collection run.
                logger.warning(
                    "Could not retrieve MFA devices for user %s: %s",
                    user["UserName"],
                    str(e),
                )
                mfa_enabled = False

            # --- Directly attached policy check ---
            try:
                attached = iam.list_attached_user_policies(UserName=user["UserName"])
                policy_names = [p["PolicyName"] for p in attached["AttachedPolicies"]]
            except ClientError as e:
                logger.warning(
                    "Could not retrieve policies for user %s: %s",
                    user["UserName"],
                    str(e),
                )
                policy_names = []

            # Determine last activity — prefer PasswordLastUsed, fall back to "never"
            last_activity = user.get("PasswordLastUsed")
            last_activity_str = last_activity.isoformat() if last_activity else "never"

            record = IdentityRecord(
                identity_id=user["UserId"],
                identity_name=user["UserName"],
                identity_type=IdentityType.HUMAN,
                provider="aws",
                status=IdentityStatus.ACTIVE,   # Will be updated by inactive analyzer
                created_at=user["CreateDate"].isoformat(),
                last_activity_at=last_activity_str,
                mfa_enabled=mfa_enabled,
                attached_policies=policy_names,
                # Mark as privileged if any admin-level policy is attached
                is_privileged=any(p in _ADMIN_POLICY_NAMES for p in policy_names),
                arn=user["Arn"],
            )
            users.append(record)

    logger.info("Collected %d IAM users from AWS", len(users))
    return users


def collect_iam_roles(session: boto3.Session) -> list[IdentityRecord]:
    """
    Collect all IAM roles (service identities) from the AWS account.

    Roles are classified as IdentityType.SERVICE since they are assumed by
    services, applications, or cross-account principals — not directly by
    human users.

    Args:
        session: Authenticated boto3 Session.

    Returns:
        List of IdentityRecord, one per IAM role.
    """
    iam = session.client("iam")
    roles: list[IdentityRecord] = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            try:
                attached = iam.list_attached_role_policies(RoleName=role["RoleName"])
                policy_names = [p["PolicyName"] for p in attached["AttachedPolicies"]]
            except ClientError as e:
                logger.warning(
                    "Could not retrieve policies for role %s: %s",
                    role["RoleName"],
                    str(e),
                )
                policy_names = []

            record = IdentityRecord(
                identity_id=role["RoleId"],
                identity_name=role["RoleName"],
                identity_type=IdentityType.SERVICE,
                provider="aws",
                status=IdentityStatus.ACTIVE,
                created_at=role["CreateDate"].isoformat(),
                # Roles don't have a password last used — activity is tracked
                # via CloudTrail (out of scope for v0.1)
                last_activity_at=None,
                mfa_enabled=False,   # Roles authenticate via temporary credentials, not MFA
                attached_policies=policy_names,
                is_privileged=any(p in _ADMIN_POLICY_NAMES for p in policy_names),
                arn=role["Arn"],
            )
            roles.append(record)

    logger.info("Collected %d IAM roles from AWS", len(roles))
    return roles


def collect_all_identities(session: boto3.Session) -> list[IdentityRecord]:
    """
    Collect all IAM identities (users and roles) from an AWS account.

    This is the primary entry point for the AWS collector, called by the CLI
    and used in integration tests.

    Args:
        session: Authenticated boto3 Session.

    Returns:
        Combined list of users and roles as IdentityRecord objects.
    """
    users = collect_iam_users(session)
    roles = collect_iam_roles(session)
    return users + roles
