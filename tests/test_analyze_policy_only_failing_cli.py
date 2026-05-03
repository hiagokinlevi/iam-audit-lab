import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_policy_default_vs_only_failing(tmp_path: Path) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FailingWildcard",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Sid": "PassingScoped",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::example-bucket/*"],
            },
        ],
    }

    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    runner = CliRunner()

    default_result = runner.invoke(
        cli,
        [
            "analyze-policy",
            "--policy-file",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert default_result.exit_code == 0, default_result.output
    default_payload = json.loads(default_result.output)

    assert isinstance(default_payload, list)
    assert len(default_payload) >= 2

    only_failing_result = runner.invoke(
        cli,
        [
            "analyze-policy",
            "--policy-file",
            str(policy_path),
            "--format",
            "json",
            "--only-failing",
        ],
    )
    assert only_failing_result.exit_code == 0, only_failing_result.output
    only_failing_payload = json.loads(only_failing_result.output)

    assert isinstance(only_failing_payload, list)
    assert len(only_failing_payload) < len(default_payload)

    serialized = json.dumps(only_failing_payload).lower()
    assert "failingwildcard" in serialized
    assert "passingscoped" not in serialized
