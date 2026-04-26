import json
from datetime import UTC, datetime, timedelta

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def _identity(name: str, last_seen: datetime) -> dict:
    return {
        "provider": "aws",
        "account_id": "123456789012",
        "identity_id": f"id-{name}",
        "identity_type": "user",
        "name": name,
        "arn": f"arn:aws:iam::123456789012:user/{name}",
        "roles": [],
        "permissions": [],
        "mfa_enabled": True,
        "last_active": last_seen.isoformat(),
        "metadata": {},
    }


def test_analyze_inactive_fail_on_findings_threshold(tmp_path):
    now = datetime.now(UTC)
    identities = [
        _identity("stale-1", now - timedelta(days=120)),
        _identity("stale-2", now - timedelta(days=100)),
        _identity("active", now - timedelta(days=5)),
    ]

    input_path = tmp_path / "identities.json"
    output_path = tmp_path / "findings.json"
    input_path.write_text(json.dumps(identities))

    runner = CliRunner()

    passing = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--inactive-days",
            "90",
            "--fail-on-findings",
            "3",
        ],
    )
    assert passing.exit_code == 0

    failing = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--inactive-days",
            "90",
            "--fail-on-findings",
            "2",
        ],
    )
    assert failing.exit_code == 2
