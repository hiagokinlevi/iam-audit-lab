from providers.gcp import normalize_gcp_member


def test_normalize_special_public_principals() -> None:
    all_users = normalize_gcp_member("allUsers")
    all_auth_users = normalize_gcp_member("allAuthenticatedUsers")

    assert all_users["member_type"] == "all_users"
    assert all_users["member_name"] == "allUsers"

    assert all_auth_users["member_type"] == "all_authenticated_users"
    assert all_auth_users["member_name"] == "allAuthenticatedUsers"
