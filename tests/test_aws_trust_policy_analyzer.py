from analyzers.aws_trust_policy_analyzer import analyze_trust_policies


def test_detects_cross_account_trust_and_wildcard():
    roles = [
        {
            "RoleName": "OpenRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
                ],
            },
        },
        {
            "RoleName": "ExternalRole",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        },
    ]

    findings = analyze_trust_policies(roles, account_id="123456789012")
    issues = {f.issue for f in findings}

    assert "wildcard_trust_principal" in issues
    assert "cross_account_trust" in issues


def test_allowed_external_account_is_downgraded():
    roles = [
        {
            "RoleName": "PartnerRole",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        }
    ]

    findings = analyze_trust_policies(
        roles,
        account_id="123456789012",
        allowed_external_accounts={"222222222222"},
    )

    assert len(findings) == 1
    assert findings[0].issue == "cross_account_trust_allowedlist"
    assert findings[0].severity == "medium"


def test_detects_federated_trust():
    roles = [
        {
            "RoleName": "OIDCRole",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                    }
                ]
            },
        }
    ]

    findings = analyze_trust_policies(roles, account_id="123456789012")
    assert any(f.issue == "federated_trust" for f in findings)
