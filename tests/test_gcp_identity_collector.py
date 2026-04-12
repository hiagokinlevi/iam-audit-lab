from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from providers.gcp import identity_collector
from schemas.identity import IdentityType


class _FakeBinding:
    def __init__(self, role: str, members: list[str]) -> None:
        self.role = role
        self.members = members


class _FakePolicy:
    def __init__(self, bindings: list[_FakeBinding]) -> None:
        self.bindings = bindings


class _FakeProjectsClient:
    def __init__(self, policy: _FakePolicy) -> None:
        self.policy = policy
        self.requested_resources: list[str] = []

    def get_iam_policy(self, request: object) -> _FakePolicy:
        self.requested_resources.append(request.resource)
        return self.policy


class _FakeGetIamPolicyRequest:
    def __init__(self, resource: str) -> None:
        self.resource = resource


def test_parse_iam_member_classifies_deleted_service_accounts() -> None:
    identity_type, identity_name, metadata = identity_collector._parse_iam_member(
        "deleted:serviceAccount:ci-bot@proj.iam.gserviceaccount.com?uid=1234567890"
    )

    assert identity_type == IdentityType.SERVICE
    assert identity_name == "ci-bot@proj.iam.gserviceaccount.com"
    assert metadata == {"memberType": "serviceAccount", "deleted": True}


def test_parse_iam_member_classifies_workload_identity_members() -> None:
    principal = (
        "principal://iam.googleapis.com/projects/123456789/locations/global/"
        "workloadIdentityPools/pool-1/subject/ns/default/sa/web"
    )
    principal_set = (
        "principalSet://iam.googleapis.com/projects/123456789/locations/global/"
        "workloadIdentityPools/pool-1/attribute.repository/example/repo"
    )

    principal_type, principal_name, principal_metadata = identity_collector._parse_iam_member(
        principal
    )
    principal_set_type, principal_set_name, principal_set_metadata = (
        identity_collector._parse_iam_member(principal_set)
    )

    assert principal_type == IdentityType.SERVICE
    assert principal_name == principal
    assert principal_metadata == {"memberType": "principal"}

    assert principal_set_type == IdentityType.GROUP
    assert principal_set_name == principal_set
    assert principal_set_metadata == {"memberType": "principalSet"}


def test_parse_iam_member_classifies_public_and_legacy_project_members() -> None:
    public_type, public_name, public_metadata = identity_collector._parse_iam_member("allUsers")
    legacy_type, legacy_name, legacy_metadata = identity_collector._parse_iam_member(
        "projectOwner:sample-project"
    )

    assert public_type == IdentityType.GROUP
    assert public_name == "allUsers"
    assert public_metadata == {"memberType": "public"}

    assert legacy_type == IdentityType.GROUP
    assert legacy_name == "projectOwner:sample-project"
    assert legacy_metadata == {"memberType": "projectOwner"}


def test_collect_iam_policy_members_normalizes_special_member_types(
    monkeypatch,
) -> None:
    deleted_service_account = (
        "deleted:serviceAccount:ci-bot@proj.iam.gserviceaccount.com?uid=1234567890"
    )
    federated_workload_set = (
        "principalSet://iam.googleapis.com/projects/123456789/locations/global/"
        "workloadIdentityPools/pool-1/attribute.repository/example/repo"
    )
    all_users = "allUsers"

    policy = _FakePolicy(
        bindings=[
            _FakeBinding("roles/editor", [deleted_service_account, deleted_service_account]),
            _FakeBinding("roles/editor", [deleted_service_account]),
            _FakeBinding("roles/iam.workloadIdentityUser", [federated_workload_set]),
            _FakeBinding("roles/viewer", [all_users]),
        ]
    )
    client = _FakeProjectsClient(policy)

    monkeypatch.setattr(identity_collector, "_get_resource_manager_client", lambda: client)

    fake_google = types.ModuleType("google")
    fake_google_iam = types.ModuleType("google.iam")
    fake_google_iam_v1 = types.ModuleType("google.iam.v1")
    fake_iam_policy_pb2 = types.ModuleType("google.iam.v1.iam_policy_pb2")
    fake_iam_policy_pb2.GetIamPolicyRequest = _FakeGetIamPolicyRequest
    fake_google_iam_v1.iam_policy_pb2 = fake_iam_policy_pb2

    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.iam", fake_google_iam)
    monkeypatch.setitem(sys.modules, "google.iam.v1", fake_google_iam_v1)
    monkeypatch.setitem(sys.modules, "google.iam.v1.iam_policy_pb2", fake_iam_policy_pb2)

    members = identity_collector.collect_iam_policy_members("sample-project")
    by_arn = {member.arn: member for member in members}

    deleted_record = by_arn[deleted_service_account]
    assert deleted_record.identity_type == IdentityType.SERVICE
    assert deleted_record.identity_name == "ci-bot@proj.iam.gserviceaccount.com"
    assert deleted_record.attached_policies == ["roles/editor"]
    assert deleted_record.is_privileged is True
    assert deleted_record.raw_metadata == {"memberType": "serviceAccount", "deleted": True}

    federated_record = by_arn[federated_workload_set]
    assert federated_record.identity_type == IdentityType.GROUP
    assert federated_record.identity_name == federated_workload_set
    assert federated_record.attached_policies == ["roles/iam.workloadIdentityUser"]
    assert federated_record.raw_metadata == {"memberType": "principalSet"}

    public_record = by_arn[all_users]
    assert public_record.identity_type == IdentityType.GROUP
    assert public_record.identity_name == "allUsers"
    assert public_record.attached_policies == ["roles/viewer"]
    assert public_record.raw_metadata == {"memberType": "public"}

    assert client.requested_resources == ["projects/sample-project"]
