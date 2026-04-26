from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_policy_fail_on_count_threshold_exit_codes(tmp_path):
    runner = CliRunner()

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    input_path = tmp_path / "policy.json"
    output_path = tmp_path / "findings.json"
    input_path.write_text(json.dumps(policy_doc), encoding="utf-8")

    below_result = runner.invoke(
        cli,
        [
            "analyze-policy",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--fail-on-count",
            "999",
        ],
    )
    assert below_result.exit_code == 0
    assert "Generated" in below_result.output

    above_result = runner.invoke(
        cli,
        [
            "analyze-policy",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--fail-on-count",
            "0",
        ],
    )
    assert above_result.exit_code == 2
    assert "Generated" in above_result.output
