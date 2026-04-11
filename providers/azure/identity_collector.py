"""
Azure Active Directory / Entra ID Identity Collector
======================================================
Collects users and service principals from Azure AD / Microsoft Entra ID.

Uses read-only Microsoft Graph API calls via azure-identity and
azure-mgmt-authorization. Requires the following permissions:
  - User.Read.All (to list users)
  - Application.Read.All (to list service principals)
  - RoleManagement.Read.All (to read role assignments)
  - Directory.Read.All (to access directory objects)

Authentication uses DefaultAzureCredential from azure-identity, which
supports environment variables, managed identity, and interactive login.

Authorization note: Only use on Azure tenants you own or are authorized to audit.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

from schemas.identity import IdentityRecord, IdentityStatus, IdentityType

logger = logging.getLogger(__name__)
GRAPH_API_HOSTS = {
    "graph.microsoft.com",
    "graph.microsoft.us",
    "dod-graph.microsoft.us",
    "microsoftgraph.chinacloudapi.cn",
}


def _get_graph_client() -> Any:
    """
    Create an authenticated Microsoft Graph client.

    Uses azure-identity DefaultAzureCredential. The credential chain is:
    1. Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
    2. Workload identity (for Azure-hosted workloads)
    3. Managed identity
    4. Azure CLI credentials
    5. Interactive browser (development only)
    """
    try:
        from azure.identity import DefaultAzureCredential
        import requests

        credential = DefaultAzureCredential()
        return credential, requests.Session()
    except ImportError:
        raise ImportError(
            "azure-identity is required for Azure collection. "
            "Install it with: pip install azure-identity"
        )


def _graph_get(credential: Any, endpoint: str, params: Optional[dict] = None) -> dict:
    """
    Make an authenticated GET request to the Microsoft Graph API.

    Args:
        credential: DefaultAzureCredential instance.
        endpoint: Graph API endpoint path (e.g., '/users').
        params: Optional query parameters.

    Returns:
        Parsed JSON response.
    """
    import requests

    # Acquire a token scoped to Graph API
    token = credential.get_token("https://graph.microsoft.com/.default")
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }

    url = f"https://graph.microsoft.com/v1.0{endpoint}"
    response = requests.get(url, headers=headers, params=params or {}, timeout=30)
    response.raise_for_status()
    return response.json()


def _normalize_graph_pagination_endpoint(page_url: str) -> str:
    """Convert a Graph nextLink URL into a safe relative endpoint."""
    parsed = urlparse(page_url)
    if not parsed.scheme and not parsed.netloc:
        return page_url
    if parsed.scheme.lower() != "https":
        raise ValueError("Microsoft Graph pagination URLs must use HTTPS.")
    if parsed.username or parsed.password:
        raise ValueError("Microsoft Graph pagination URLs must not embed credentials.")

    hostname = (parsed.hostname or "").strip().lower()
    if hostname not in GRAPH_API_HOSTS:
        raise ValueError(f"Unexpected Microsoft Graph pagination host: {hostname or '<missing>'}")
    if not parsed.path.startswith("/"):
        raise ValueError("Microsoft Graph pagination URLs must include an absolute path.")

    if parsed.query:
        return f"{parsed.path}?{parsed.query}"
    return parsed.path


def collect_azure_users(tenant_id: str) -> list[IdentityRecord]:
    """
    Collect all Azure AD users from the specified tenant.

    Retrieves user display name, UPN, account status, and sign-in activity.
    MFA status requires additional API calls (Azure AD Premium required) —
    this implementation records mfa_enabled=False as a conservative default.

    Args:
        tenant_id: Azure AD tenant ID (GUID).

    Returns:
        List of IdentityRecord, one per user.
    """
    try:
        credential, _ = _get_graph_client()
    except ImportError as e:
        logger.error("Cannot collect Azure users: %s", str(e))
        return []

    users: list[IdentityRecord] = []
    params = {
        # Select only the fields we need — minimizes data transfer
        "$select": "id,displayName,userPrincipalName,accountEnabled,createdDateTime,"
                   "signInActivity,assignedLicenses",
        "$top": 999,
    }

    try:
        page_url = "/users"
        while page_url:
            # Handle paged responses — Graph API uses @odata.nextLink for pagination
            endpoint = _normalize_graph_pagination_endpoint(page_url)
            request_params = params if endpoint == page_url else None
            data = _graph_get(credential, endpoint, request_params)

            for user in data.get("value", []):
                # Extract last sign-in from signInActivity (requires Azure AD P1/P2)
                sign_in_activity = user.get("signInActivity") or {}
                last_sign_in = sign_in_activity.get("lastSignInDateTime")

                record = IdentityRecord(
                    identity_id=user["id"],
                    identity_name=user.get("displayName") or user.get("userPrincipalName", ""),
                    identity_type=IdentityType.HUMAN,
                    provider="azure",
                    status=(
                        IdentityStatus.ACTIVE
                        if user.get("accountEnabled", False)
                        else IdentityStatus.DISABLED
                    ),
                    created_at=user.get("createdDateTime"),
                    last_activity_at=last_sign_in or "never",
                    # MFA status requires a separate API call (Graph API: /users/{id}/authentication/methods)
                    # This is a known gap — set to False conservatively.
                    mfa_enabled=False,
                    attached_policies=[],   # Role assignments collected separately
                    arn=user.get("userPrincipalName"),  # UPN serves as the unique identifier
                )
                users.append(record)

            # Follow pagination
            page_url = data.get("@odata.nextLink", "")

    except Exception as e:
        logger.error("Error collecting Azure users: %s", str(e))

    logger.info("Collected %d Azure AD users from tenant %s", len(users), tenant_id)
    return users


def collect_service_principals(tenant_id: str) -> list[IdentityRecord]:
    """
    Collect all service principals (applications and managed identities) from Azure AD.

    Service principals are the Azure equivalent of AWS service accounts or GCP service accounts.

    Args:
        tenant_id: Azure AD tenant ID (GUID).

    Returns:
        List of IdentityRecord, one per service principal.
    """
    try:
        credential, _ = _get_graph_client()
    except ImportError as e:
        logger.error("Cannot collect Azure service principals: %s", str(e))
        return []

    principals: list[IdentityRecord] = []
    params = {
        "$select": "id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime",
        "$top": 999,
    }

    try:
        page_url = "/servicePrincipals"
        while page_url:
            endpoint = _normalize_graph_pagination_endpoint(page_url)
            request_params = params if endpoint == page_url else None
            data = _graph_get(credential, endpoint, request_params)

            for sp in data.get("value", []):
                record = IdentityRecord(
                    identity_id=sp["id"],
                    identity_name=sp.get("displayName", sp["appId"]),
                    identity_type=IdentityType.SERVICE,
                    provider="azure",
                    status=(
                        IdentityStatus.ACTIVE
                        if sp.get("accountEnabled", False)
                        else IdentityStatus.DISABLED
                    ),
                    created_at=sp.get("createdDateTime"),
                    last_activity_at=None,  # Not available via Graph API without sign-in logs
                    mfa_enabled=False,      # Not applicable to service principals
                    raw_metadata={
                        "servicePrincipalType": sp.get("servicePrincipalType"),
                        "appId": sp.get("appId"),
                    },
                )
                principals.append(record)

            page_url = data.get("@odata.nextLink", "")

    except Exception as e:
        logger.error("Error collecting service principals: %s", str(e))

    logger.info(
        "Collected %d Azure service principals from tenant %s", len(principals), tenant_id
    )
    return principals


def collect_all_identities(tenant_id: str) -> list[IdentityRecord]:
    """
    Collect all Azure AD identities (users and service principals).

    Entry point for the Azure provider, called by the CLI.
    """
    users = collect_azure_users(tenant_id)
    principals = collect_service_principals(tenant_id)
    return users + principals
