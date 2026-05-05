from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_policy_json_format_and_threshold_exit(tmp_path):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "analyze-policy",
            "--policy-file",
            str(policy_file),
            "--format",
            "json",
            "--max-high",
            "0",
        ],
    )

    assert result.exit_code != 0

    output = result.output
    start = output.find("[")
    end = output.rfind("]")
    assert start != -1 and end != -1 and end > start

    payload = json.loads(output[start : end + 1])
    assert isinstance(payload, list)
    assert payload, "expected at least one finding"

    finding = payload[0]
    assert isinstance(finding, dict)
    assert "severity" in finding
    assert "rule_id" in finding
