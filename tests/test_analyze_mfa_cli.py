from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_mfa_default_table_output(tmp_path):
    data = [
        {
            "provider": "aws",
            "account_id": "111111111111",
            "identity_type": "user",
            "name": "alice",
            "mfa_enabled": True,
            "is_privileged": False,
        },
        {
            "provider": "aws",
            "account_id": "111111111111",
            "identity_type": "user",
            "name": "admin",
            "mfa_enabled": False,
            "is_privileged": True,
        },
    ]
    input_file = tmp_path / "identities.json"
    input_file.write_text(json.dumps(data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-mfa", "--input", str(input_file)])

    assert result.exit_code == 0
    assert "MFA Coverage Summary" in result.output
    assert "Total identities:" in result.output
    assert "Privileged identities without MFA" in result.output
    assert "aws:admin" in result.output


def test_analyze_mfa_json_output(tmp_path):
    data = [
        {
            "provider": "aws",
            "account_id": "111111111111",
            "identity_type": "user",
            "name": "alice",
            "mfa_enabled": True,
            "is_privileged": False,
        },
        {
            "provider": "aws",
            "account_id": "111111111111",
            "identity_type": "user",
            "name": "admin",
            "mfa_enabled": False,
            "is_privileged": True,
        },
    ]
    input_file = tmp_path / "identities.json"
    input_file.write_text(json.dumps(data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-mfa", "--input", str(input_file), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total_identities"] == 2
    assert payload["mfa_enabled"] == 1
    assert payload["mfa_missing"] == 1


def test_analyze_mfa_invalid_format(tmp_path):
    data = []
    input_file = tmp_path / "identities.json"
    input_file.write_text(json.dumps(data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-mfa", "--input", str(input_file), "--format", "yaml"])

    assert result.exit_code != 0
    assert "Invalid value for '--format'" in result.output
