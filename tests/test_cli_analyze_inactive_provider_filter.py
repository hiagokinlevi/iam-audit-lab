import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_inactive_provider_filter_changes_findings(tmp_path: Path) -> None:
    identities = [
        {
            "provider": "aws",
            "account_id": "111111111111",
            "principal_id": "aws-user-1",
            "principal_name": "aws-user-1",
            "principal_type": "user",
            "is_active": True,
            "last_activity": "2023-01-01T00:00:00Z",
            "mfa_enabled": False,
            "roles": [],
            "permissions": [],
            "metadata": {},
        },
        {
            "provider": "gcp",
            "account_id": "project-1",
            "principal_id": "gcp-sa-1",
            "principal_name": "gcp-sa-1",
            "principal_type": "service_account",
            "is_active": True,
            "last_activity": "2023-01-01T00:00:00Z",
            "mfa_enabled": False,
            "roles": [],
            "permissions": [],
            "metadata": {},
        },
    ]

    input_file = tmp_path / "identities.json"
    input_file.write_text(json.dumps(identities))

    runner = CliRunner()

    output_all = tmp_path / "findings-all.json"
    result_all = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_file),
            "--output",
            str(output_all),
            "--days",
            "30",
        ],
    )
    assert result_all.exit_code == 0, result_all.output
    all_findings = json.loads(output_all.read_text())
    assert len(all_findings) == 2

    output_filtered = tmp_path / "findings-aws.json"
    result_filtered = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_file),
            "--output",
            str(output_filtered),
            "--days",
            "30",
            "--provider",
            "aws",
        ],
    )
    assert result_filtered.exit_code == 0, result_filtered.output
    filtered_findings = json.loads(output_filtered.read_text())
    assert len(filtered_findings) == 1
    dumped = json.dumps(filtered_findings).lower()
    assert "aws" in dumped
    assert "gcp" not in dumped
