import json

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


def test_analyze_mfa_json_output_structure_and_exit(tmp_path):
    identities = [
        {
            "provider": "aws",
            "account_id": "123456789012",
            "principal_id": "alice",
            "principal_type": "user",
            "display_name": "alice",
            "is_privileged": True,
            "mfa_enabled": False,
        }
    ]

    input_file = tmp_path / "identities.json"
    input_file.write_text(json.dumps(identities))

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-mfa", "--input", str(input_file), "--json"])

    assert result.exit_code == 0

    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert payload, "expected at least one finding"

    first = payload[0]
    assert "title" in first
    assert "severity" in first
    assert "resource_id" in first
