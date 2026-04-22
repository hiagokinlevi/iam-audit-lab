from __future__ import annotations

from typing import Any


def normalize_gcp_member(member: str) -> dict[str, str]:
    """Normalize a raw GCP IAM member string into structured fields.

    Examples:
      - user:alice@example.com
      - serviceAccount:sa@project.iam.gserviceaccount.com
      - allUsers
      - allAuthenticatedUsers
    """
    if member == "allUsers":
        return {"member_type": "all_users", "member_name": "allUsers"}

    if member == "allAuthenticatedUsers":
        return {
            "member_type": "all_authenticated_users",
            "member_name": "allAuthenticatedUsers",
        }

    if ":" in member:
        member_type, member_name = member.split(":", 1)
        return {"member_type": member_type, "member_name": member_name}

    return {"member_type": "unknown", "member_name": member}


def parse_gcp_binding_members(binding: dict[str, Any]) -> list[dict[str, str]]:
    """Parse members from a GCP IAM binding into normalized member entries."""
    members = binding.get("members", []) or []
    return [normalize_gcp_member(m) for m in members if isinstance(m, str)]
