import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_inactive_json_output_structure_and_fields(tmp_path):
    input_file = tmp_path / "identities.json"
    input_file.write_text(
        json.dumps(
            [
                {
                    "provider": "aws",
                    "identity_id": "user-123",
                    "identity_name": "stale-user",
                    "identity_type": "user",
                    "is_privileged": False,
                    "mfa_enabled": False,
                    "last_active": "2023-01-01T00:00:00Z",
                    "roles": ["ReadOnlyAccess"],
                    "metadata": {},
                }
            ]
        )
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_file),
            "--days",
            "30",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 1

    finding = payload[0]
    assert finding["provider"] == "aws"
    assert finding["identity_id"] == "user-123"
    assert "inactive" in finding["issue"].lower()
    assert finding["inactive_days"] >= 30
