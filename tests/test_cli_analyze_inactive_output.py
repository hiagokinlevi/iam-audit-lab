import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_inactive_writes_output_file(tmp_path: Path) -> None:
    identities = [
        {
            "provider": "aws",
            "account_id": "123456789012",
            "identity_type": "user",
            "name": "inactive-user",
            "arn_or_id": "arn:aws:iam::123456789012:user/inactive-user",
            "roles": [],
            "policies": [],
            "mfa_enabled": False,
            "last_activity": "2023-01-01T00:00:00Z",
            "created_at": "2022-01-01T00:00:00Z",
            "metadata": {},
        }
    ]

    input_file = tmp_path / "identities.json"
    output_file = tmp_path / "inactive-findings.json"
    input_file.write_text(json.dumps(identities), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_file),
            "--days",
            "30",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_file.exists()

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data, "Expected at least one inactive finding in exported output"
    assert isinstance(data[0], dict)
