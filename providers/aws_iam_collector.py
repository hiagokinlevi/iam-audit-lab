import json
import os
from typing import Dict, List, Any

import boto3


def _write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _get_inline_user_policies(iam, user_name: str) -> List[Dict[str, Any]]:
    policies = []
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=user_name):
        for name in page.get("PolicyNames", []):
            doc = iam.get_user_policy(UserName=user_name, PolicyName=name)
            policies.append(
                {
                    "policy_name": name,
                    "document": doc.get("PolicyDocument"),
                }
            )
    return policies


def _get_inline_role_policies(iam, role_name: str) -> List[Dict[str, Any]]:
    policies = []
    paginator = iam.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for name in page.get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)
            policies.append(
                {
                    "policy_name": name,
                    "document": doc.get("PolicyDocument"),
                }
            )
    return policies


def _get_inline_group_policies(iam, group_name: str) -> List[Dict[str, Any]]:
    policies = []
    paginator = iam.get_paginator("list_group_policies")
    for page in paginator.paginate(GroupName=group_name):
        for name in page.get("PolicyNames", []):
            doc = iam.get_group_policy(GroupName=group_name, PolicyName=name)
            policies.append(
                {
                    "policy_name": name,
                    "document": doc.get("PolicyDocument"),
                }
            )
    return policies


def collect_iam_data(profile: str | None = None, region: str | None = None) -> Dict[str, Any]:
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    users: List[Dict[str, Any]] = []
    roles: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []

    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for u in page.get("Users", []):
            name = u["UserName"]

            attached = iam.list_attached_user_policies(UserName=name).get(
                "AttachedPolicies", []
            )

            groups_resp = iam.list_groups_for_user(UserName=name).get("Groups", [])

            users.append(
                {
                    "user_name": name,
                    "arn": u.get("Arn"),
                    "create_date": u.get("CreateDate"),
                    "groups": [g["GroupName"] for g in groups_resp],
                    "attached_managed_policies": attached,
                    "inline_policies": _get_inline_user_policies(iam, name),
                }
            )

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for r in page.get("Roles", []):
            name = r["RoleName"]

            attached = iam.list_attached_role_policies(RoleName=name).get(
                "AttachedPolicies", []
            )

            roles.append(
                {
                    "role_name": name,
                    "arn": r.get("Arn"),
                    "create_date": r.get("CreateDate"),
                    "assume_role_policy": r.get("AssumeRolePolicyDocument"),
                    "attached_managed_policies": attached,
                    "inline_policies": _get_inline_role_policies(iam, name),
                }
            )

    group_paginator = iam.get_paginator("list_groups")
    for page in group_paginator.paginate():
        for g in page.get("Groups", []):
            name = g["GroupName"]

            attached = iam.list_attached_group_policies(GroupName=name).get(
                "AttachedPolicies", []
            )

            members = iam.get_group(GroupName=name).get("Users", [])

            groups.append(
                {
                    "group_name": name,
                    "arn": g.get("Arn"),
                    "create_date": g.get("CreateDate"),
                    "members": [u["UserName"] for u in members],
                    "attached_managed_policies": attached,
                    "inline_policies": _get_inline_group_policies(iam, name),
                }
            )

    return {"users": users, "roles": roles, "groups": groups}


def export_iam_json(output_dir: str, profile: str | None = None, region: str | None = None) -> None:
    data = collect_iam_data(profile=profile, region=region)

    _write_json(os.path.join(output_dir, "aws_iam_users.json"), data["users"])
    _write_json(os.path.join(output_dir, "aws_iam_roles.json"), data["roles"])
    _write_json(os.path.join(output_dir, "aws_iam_groups.json"), data["groups"])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect AWS IAM identities and policies")
    parser.add_argument("--output-dir", default="reports/aws", help="Directory to write JSON files")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument("--region", default=None, help="AWS region")

    args = parser.parse_args()

    export_iam_json(args.output_dir, profile=args.profile, region=args.region)
