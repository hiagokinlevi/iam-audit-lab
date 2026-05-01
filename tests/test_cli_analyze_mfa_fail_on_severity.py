import json

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


def _write_identities(path):
    path.write_text(
        json.dumps(
            [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "identity_id": "alice",
                    "identity_type": "user",
                    "display_name": "alice",
                    "mfa_enabled": False,
                    "is_privileged": True,
                }
            ]
        ),
        encoding="utf-8",
    )


def test_analyze_mfa_fail_on_severity_pass_and_fail(tmp_path):
    runner = CliRunner()
    input_path = tmp_path / "identities.json"
    output_path = tmp_path / "findings.json"
    _write_identities(input_path)

    pass_result = runner.invoke(
        cli,
        [
            "analyze-mfa",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--fail-on-severity",
            "critical",
        ],
    )
    assert pass_result.exit_code == 0

    fail_result = runner.invoke(
        cli,
        [
            "analyze-mfa",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--fail-on-severity",
            "low",
        ],
    )
    assert fail_result.exit_code != 0
