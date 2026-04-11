from __future__ import annotations

import json

from click.testing import CliRunner

from analyzers.aws_password_policy_analyzer import analyze_password_policy
from cli.main import cli


def _strong_policy() -> dict:
    return {
        "MinimumPasswordLength": 14,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
        "PasswordReusePrevention": 24,
        "ExpirePasswords": True,
        "MaxPasswordAge": 90,
        "AllowUsersToChangePassword": True,
    }


def test_missing_password_policy_is_high_risk() -> None:
    result = analyze_password_policy(None, account_id="123456789012")

    assert result.account_id == "123456789012"
    assert result.risk_score == 35
    assert [finding.rule_id for finding in result.findings] == ["PW-001"]


def test_strong_password_policy_has_no_findings() -> None:
    result = analyze_password_policy(_strong_policy(), account_id="123456789012")

    assert result.findings == []
    assert result.risk_score == 0


def test_weak_password_policy_flags_length_complexity_and_reuse() -> None:
    policy = _strong_policy() | {
        "MinimumPasswordLength": 8,
        "RequireSymbols": False,
        "PasswordReusePrevention": 5,
    }

    result = analyze_password_policy(policy)

    assert [finding.rule_id for finding in result.findings] == ["PW-002", "PW-003", "PW-004"]
    assert result.risk_score == 60


def test_passwords_that_never_expire_are_flagged() -> None:
    policy = _strong_policy() | {
        "ExpirePasswords": False,
        "MaxPasswordAge": 0,
    }

    result = analyze_password_policy(policy)

    assert [finding.rule_id for finding in result.findings] == ["PW-006"]
    assert result.risk_score == 20


def test_password_expiration_over_90_days_is_flagged() -> None:
    policy = _strong_policy() | {"MaxPasswordAge": 120}

    result = analyze_password_policy(policy)

    assert [finding.rule_id for finding in result.findings] == ["PW-006"]
    assert result.findings[0].severity == "MEDIUM"
    assert "120" in result.findings[0].detail


def test_cli_analyze_password_policy_json_output() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password-policy.json", "w", encoding="utf-8") as handle:
            json.dump({"PasswordPolicy": _strong_policy() | {"MinimumPasswordLength": 10}}, handle)

        result = runner.invoke(
            cli,
            [
                "analyze-password-policy",
                "--policy-file",
                "password-policy.json",
                "--account-id",
                "123456789012",
                "--json-output",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["account_id"] == "123456789012"
    assert payload["findings"][0]["rule_id"] == "PW-002"


def test_cli_analyze_password_policy_fail_on_medium_exits_nonzero() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("password-policy.json", "w", encoding="utf-8") as handle:
            json.dump({"PasswordPolicy": _strong_policy() | {"RequireNumbers": False}}, handle)

        result = runner.invoke(
            cli,
            [
                "analyze-password-policy",
                "--policy-file",
                "password-policy.json",
                "--fail-on",
                "medium",
            ],
        )

    assert result.exit_code != 0
    assert "Password policy findings met --fail-on medium" in result.output
