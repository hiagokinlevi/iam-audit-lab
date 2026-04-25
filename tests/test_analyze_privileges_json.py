from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


def test_analyze_privileges_json_schema_and_exit_code(tmp_path):
    input_file = tmp_path / "identities.json"
    # Minimal normalized identity shape; analyzer may or may not emit findings depending on logic.
    input_file.write_text(
        json.dumps(
            [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "principal_id": "alice",
                    "principal_type": "user",
                    "display_name": "alice",
                    "roles": ["AdministratorAccess"],
                    "mfa_enabled": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-privileges", "--input", str(input_file), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, dict)
    assert "finding_count" in payload
    assert "findings" in payload
    assert isinstance(payload["findings"], list)

    for finding in payload["findings"]:
        assert "severity" in finding
        assert "finding_type" in finding
        assert "principal_id" in finding
        assert "account_id" in finding
        assert "risk_metadata" in finding
