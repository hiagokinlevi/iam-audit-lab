from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from providers.azure import identity_collector


def test_normalize_graph_pagination_endpoint_accepts_relative_paths() -> None:
    endpoint = identity_collector._normalize_graph_pagination_endpoint("/users?$skiptoken=abc")

    assert endpoint == "/users?$skiptoken=abc"


def test_normalize_graph_pagination_endpoint_rejects_relative_paths_without_leading_slash() -> None:
    with pytest.raises(ValueError, match="must start with '/'"):
        identity_collector._normalize_graph_pagination_endpoint("users?$skiptoken=abc")


def test_normalize_graph_pagination_endpoint_allows_known_graph_hosts() -> None:
    endpoint = identity_collector._normalize_graph_pagination_endpoint(
        "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    )

    assert endpoint == "/v1.0/users?$skiptoken=abc"


def test_normalize_graph_pagination_endpoint_rejects_unexpected_relative_paths() -> None:
    with pytest.raises(ValueError, match="Unexpected Microsoft Graph pagination path"):
        identity_collector._normalize_graph_pagination_endpoint("/applications?$skiptoken=abc")


def test_build_graph_api_url_prefixes_unversioned_endpoints() -> None:
    url = identity_collector._build_graph_api_url("/users?$skiptoken=abc")

    assert url == "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"


def test_build_graph_api_url_preserves_explicit_graph_versions() -> None:
    v1_url = identity_collector._build_graph_api_url("/v1.0/users?$skiptoken=abc")
    beta_url = identity_collector._build_graph_api_url("/beta/users?$skiptoken=abc")

    assert v1_url == "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    assert beta_url == "https://graph.microsoft.com/beta/users?$skiptoken=abc"


def test_normalize_graph_pagination_endpoint_rejects_unexpected_hosts() -> None:
    with pytest.raises(ValueError, match="Unexpected Microsoft Graph pagination host"):
        identity_collector._normalize_graph_pagination_endpoint(
            "https://169.254.169.254/metadata/identity/oauth2/token"
        )


def test_normalize_graph_pagination_endpoint_rejects_non_default_https_ports() -> None:
    with pytest.raises(ValueError, match="default HTTPS port"):
        identity_collector._normalize_graph_pagination_endpoint(
            "https://graph.microsoft.com:444/v1.0/users?$skiptoken=abc"
        )


def test_normalize_graph_pagination_endpoint_rejects_path_parameters() -> None:
    with pytest.raises(ValueError, match="path parameters"):
        identity_collector._normalize_graph_pagination_endpoint(
            "https://graph.microsoft.com/v1.0/users;param?$skiptoken=abc"
        )


def test_normalize_graph_pagination_endpoint_rejects_fragments() -> None:
    with pytest.raises(ValueError, match="must not include fragments"):
        identity_collector._normalize_graph_pagination_endpoint(
            "https://graph.microsoft.com/v1.0/users?$skiptoken=abc#fragment"
        )


def test_collect_azure_users_normalizes_safe_next_links(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict | None]] = []
    pages = [
        {
            "value": [
                {
                    "id": "user-1",
                    "displayName": "Alice",
                    "userPrincipalName": "alice@contoso.com",
                    "accountEnabled": True,
                    "createdDateTime": "2026-01-01T00:00:00Z",
                    "signInActivity": {"lastSignInDateTime": "2026-04-10T00:00:00Z"},
                    "assignedLicenses": [],
                }
            ],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=abc",
        },
        {
            "value": [
                {
                    "id": "user-2",
                    "displayName": "Bob",
                    "userPrincipalName": "bob@contoso.com",
                    "accountEnabled": False,
                    "createdDateTime": "2026-01-02T00:00:00Z",
                    "assignedLicenses": [],
                }
            ]
        },
    ]

    monkeypatch.setattr(identity_collector, "_get_graph_client", lambda: (object(), None))

    def fake_graph_get(_credential: object, endpoint: str, params: dict | None = None) -> dict:
        calls.append((endpoint, params))
        return pages.pop(0)

    monkeypatch.setattr(identity_collector, "_graph_get", fake_graph_get)

    users = identity_collector.collect_azure_users("tenant-123")

    assert [user.identity_id for user in users] == ["user-1", "user-2"]
    assert calls == [
        (
            "/users",
            {
                "$select": (
                    "id,displayName,userPrincipalName,accountEnabled,createdDateTime,"
                    "signInActivity,assignedLicenses"
                ),
                "$top": 999,
            },
        ),
        ("/v1.0/users?$skiptoken=abc", None),
    ]


def test_collect_service_principals_rejects_external_next_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict | None]] = []

    monkeypatch.setattr(identity_collector, "_get_graph_client", lambda: (object(), None))

    def fake_graph_get(_credential: object, endpoint: str, params: dict | None = None) -> dict:
        calls.append((endpoint, params))
        return {
            "value": [
                {
                    "id": "sp-1",
                    "displayName": "Deploy Bot",
                    "appId": "app-1",
                    "servicePrincipalType": "Application",
                    "accountEnabled": True,
                    "createdDateTime": "2026-01-03T00:00:00Z",
                }
            ],
            "@odata.nextLink": "https://evil.example.com/v1.0/servicePrincipals?$skiptoken=abc",
        }

    monkeypatch.setattr(identity_collector, "_graph_get", fake_graph_get)

    principals = identity_collector.collect_service_principals("tenant-123")

    assert [principal.identity_id for principal in principals] == ["sp-1"]
    assert calls == [
        (
            "/servicePrincipals",
            {
                "$select": (
                    "id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime"
                ),
                "$top": 999,
            },
        )
    ]
