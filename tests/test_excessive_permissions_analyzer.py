from analyzers.excessive_permissions import analyze_excessive_permissions


def test_detects_effective_admin_access_patterns():
    identities = [
        {
            "id": "u-1",
            "provider": "aws",
            "identity_type": "user",
            "display_name": "alice",
            "attached_policies": ["ReadOnlyAccess", "AdministratorAccess"],
            "inline_policy_actions": [],
        },
        {
            "id": "r-1",
            "provider": "aws",
            "identity_type": "role",
            "display_name": "ops-role",
            "attached_policies": [],
            "inline_policy_actions": ["iam:*"],
        },
        {
            "id": "r-2",
            "provider": "aws",
            "identity_type": "role",
            "display_name": "platform-role",
            "attached_policies": [],
            "inline_policy_actions": ["ec2:Describe*", "*:*"],
        },
    ]

    findings = analyze_excessive_permissions(identities)
    by_identity = {f["identity_id"]: f for f in findings}

    assert "u-1" in by_identity
    assert "r-1" in by_identity
    assert "r-2" in by_identity

    assert "AdministratorAccess" in by_identity["u-1"]["evidence"]
    assert "iam:*" in by_identity["r-1"]["evidence"]
    assert "*:*" in by_identity["r-2"]["evidence"]
