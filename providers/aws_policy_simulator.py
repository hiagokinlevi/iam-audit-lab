"""AWS IAM Policy Simulator integration.

Provides a small helper to evaluate whether high-risk actions are actually
allowed for an IAM principal using the IAM Policy Simulator API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import boto3


HIGH_RISK_ACTIONS: tuple[str, ...] = (
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "organizations:CreateAccount",
    "kms:ScheduleKeyDeletion",
)


@dataclass(frozen=True)
class SimulationResult:
    principal_arn: str
    evaluated_actions: list[str]
    allowed_actions: list[str]
    denied_actions: list[str]


class AWSPolicySimulator:
    """Wrapper around IAM simulate_principal_policy for effective permission checks."""

    def __init__(self, iam_client=None):
        self.iam = iam_client or boto3.client("iam")

    def simulate_high_risk_actions(
        self,
        principal_arn: str,
        actions: Iterable[str] | None = None,
    ) -> SimulationResult:
        action_list = list(actions or HIGH_RISK_ACTIONS)
        if not action_list:
            return SimulationResult(
                principal_arn=principal_arn,
                evaluated_actions=[],
                allowed_actions=[],
                denied_actions=[],
            )

        paginator = self.iam.get_paginator("simulate_principal_policy")
        allowed: list[str] = []
        denied: list[str] = []

        for page in paginator.paginate(
            PolicySourceArn=principal_arn,
            ActionNames=action_list,
        ):
            for item in page.get("EvaluationResults", []):
                action_name = item.get("EvalActionName")
                decision = item.get("EvalDecision", "implicitDeny")
                if not action_name:
                    continue
                if str(decision).lower() == "allowed":
                    allowed.append(action_name)
                else:
                    denied.append(action_name)

        # Keep deterministic ordering by input action list
        allowed_set = set(allowed)
        denied_set = set(denied)
        ordered_allowed = [a for a in action_list if a in allowed_set]
        ordered_denied = [a for a in action_list if a in denied_set and a not in allowed_set]

        return SimulationResult(
            principal_arn=principal_arn,
            evaluated_actions=action_list,
            allowed_actions=ordered_allowed,
            denied_actions=ordered_denied,
        )
