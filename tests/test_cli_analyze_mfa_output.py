from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_mfa_writes_output_file(tmp_path):
    runner = CliRunner()

    input_data = [
        {
            "provider": "aws",
            "account_id": "123456789012",
            "identity_type": "user",
            "identity_name": "alice",
            "mfa_enabled": False,
            "is_privileged": True,
        },
        {
            "provider": "aws",
            "account_id": "123456789012",
            "identity_type": "user",
            "identity_name": "bob",
            "mfa_enabled": True,
            "is_privileged": False,
        },
    ]

    input_path = tmp_path / "identities.json"
    input_path.write_text(json.dumps(input_data), encoding="utf-8")

    output_path = tmp_path / "mfa-results.json"

    result = runner.invoke(
        cli,
        [
            "analyze-mfa",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert "coverage_percent" in payload
    assert "total_identities" in payload
    assert "findings" in payload
    assert isinstance(payload["findings"], list)
