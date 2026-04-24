import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_generate_report_json_output_contains_expected_sections(tmp_path: Path) -> None:
    runner = CliRunner()

    input_file = tmp_path / "identities.json"
    identities = [
        {
            "provider": "aws",
            "account_id": "123456789012",
            "identity_id": "alice",
            "identity_type": "user",
            "display_name": "alice",
            "is_privileged": True,
            "mfa_enabled": False,
            "last_active": None,
            "raw": {},
        },
        {
            "provider": "aws",
            "account_id": "123456789012",
            "identity_id": "readonly-role",
            "identity_type": "role",
            "display_name": "readonly-role",
            "is_privileged": False,
            "mfa_enabled": None,
            "last_active": None,
            "raw": {},
        },
    ]
    input_file.write_text(json.dumps(identities), encoding="utf-8")

    result = runner.invoke(
        cli,
        [
            "generate-report",
            "--input",
            str(input_file),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    assert "executive_summary" in payload
    assert "findings_by_severity" in payload
    assert "key_coverage_metrics" in payload

    assert isinstance(payload["executive_summary"], dict)
    assert isinstance(payload["findings_by_severity"], dict)
    assert isinstance(payload["key_coverage_metrics"], dict)
