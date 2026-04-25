import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_generate_report_json_success_and_extension_mismatch(tmp_path):
    runner = CliRunner()

    input_payload = {
        "identities": [
            {
                "provider": "aws",
                "account_id": "123456789012",
                "principal_id": "alice",
                "principal_type": "user",
                "display_name": "Alice",
                "is_active": True,
                "mfa_enabled": True,
                "last_activity": None,
                "roles": ["AdministratorAccess"],
                "permissions": ["*"],
                "metadata": {},
            }
        ],
        "findings": [],
    }

    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(input_payload), encoding="utf-8")

    json_output = tmp_path / "report.json"
    ok = runner.invoke(
        cli,
        [
            "generate-report",
            "--input",
            str(input_file),
            "--output",
            str(json_output),
            "--format",
            "json",
        ],
    )

    assert ok.exit_code == 0, ok.output
    assert json_output.exists()
    rendered = json.loads(json_output.read_text(encoding="utf-8"))
    assert "identities" in rendered
    assert rendered["identities"][0]["principal_id"] == "alice"

    mismatch = runner.invoke(
        cli,
        [
            "generate-report",
            "--input",
            str(input_file),
            "--output",
            str(tmp_path / "report.md"),
            "--format",
            "json",
        ],
    )

    assert mismatch.exit_code != 0
    assert "Output file extension must be '.json'" in mismatch.output
