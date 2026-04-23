import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_privileges_fail_on_severity_gates_ci(tmp_path):
    runner = CliRunner()

    identities_path = tmp_path / "identities.json"
    findings_path = tmp_path / "findings.json"

    # Include one clearly privileged identity expected to trigger a high/critical-style finding
    identities = [
        {
            "id": "u-1",
            "provider": "aws",
            "identity_type": "user",
            "name": "admin-user",
            "roles": ["AdministratorAccess"],
            "mfa_enabled": True,
            "last_active": "2026-01-01T00:00:00Z",
        }
    ]
    identities_path.write_text(json.dumps(identities), encoding="utf-8")

    pass_result = runner.invoke(
        cli,
        [
            "analyze-privileges",
            "--input",
            str(identities_path),
            "--output",
            str(findings_path),
            "--fail-on-severity",
            "critical",
        ],
    )

    fail_result = runner.invoke(
        cli,
        [
            "analyze-privileges",
            "--input",
            str(identities_path),
            "--output",
            str(findings_path),
            "--fail-on-severity",
            "medium",
        ],
    )

    assert pass_result.exit_code == 0
    assert fail_result.exit_code != 0
