from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_mfa_provider_filter_only_analyzes_matching_provider(tmp_path: Path) -> None:
    input_path = tmp_path / "identities.json"
    output_path = tmp_path / "findings.json"

    identities = [
        {
            "id": "aws-user-1",
            "provider": "aws",
            "identity_type": "user",
            "name": "aws-user-1",
            "privileged": True,
            "mfa_enabled": False,
        },
        {
            "id": "azure-user-1",
            "provider": "azure",
            "identity_type": "user",
            "name": "azure-user-1",
            "privileged": True,
            "mfa_enabled": False,
        },
    ]

    input_path.write_text(json.dumps(identities), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "analyze-mfa",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--provider",
            "aws",
        ],
    )

    assert result.exit_code == 0, result.output
    findings = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(findings) == 1
    finding_str = json.dumps(findings[0])
    assert "aws-user-1" in finding_str
    assert "azure-user-1" not in finding_str
