import json

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


def test_analyze_policy_json_output_shape(tmp_path):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAll",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-policy", "--policy-file", str(policy_file), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, dict)
    assert "findings" in payload
    assert isinstance(payload["findings"], list)
    if payload["findings"]:
        finding = payload["findings"][0]
        assert "rule_id" in finding
        assert "severity" in finding
        assert "statement" in finding
        assert "message" in finding
        assert "sid" in finding["statement"]
        assert "index" in finding["statement"]
