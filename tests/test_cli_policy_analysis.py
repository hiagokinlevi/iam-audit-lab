from __future__ import annotations

import json

from click.testing import CliRunner

from cli.main import cli


def test_analyze_policy_json_output_flags_passrole_wildcard() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("policy.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    ],
                },
                handle,
            )

        result = runner.invoke(
            cli,
            [
                "analyze-policy",
                "--policy-file",
                "policy.json",
                "--policy-name",
                "PassRolePolicy",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["policy_name"] == "PassRolePolicy"
    assert payload["risk_tier"] == "HIGH"
    assert payload["checks_fired"][0]["check_id"] == "IAMP-008"


def test_analyze_policy_fail_on_high_exits_nonzero() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("policy.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    ],
                },
                handle,
            )

        result = runner.invoke(
            cli,
            [
                "analyze-policy",
                "--policy-file",
                "policy.json",
                "--fail-on",
                "high",
            ],
        )

    assert result.exit_code != 0
    assert "Policy risk tier HIGH meets --fail-on HIGH" in result.output


def test_analyze_policy_rejects_malformed_json() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("policy.json", "w", encoding="utf-8") as handle:
            handle.write("{bad json")

        result = runner.invoke(
            cli,
            [
                "analyze-policy",
                "--policy-file",
                "policy.json",
            ],
        )

    assert result.exit_code != 0
    assert "Policy file must contain valid JSON" in result.output


def test_analyze_policy_rejects_non_object_payload() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("policy.json", "w", encoding="utf-8") as handle:
            json.dump([{"Effect": "Allow", "Action": "*", "Resource": "*"}], handle)

        result = runner.invoke(
            cli,
            [
                "analyze-policy",
                "--policy-file",
                "policy.json",
            ],
        )

    assert result.exit_code != 0
    assert "Policy file must contain a top-level JSON object" in result.output
