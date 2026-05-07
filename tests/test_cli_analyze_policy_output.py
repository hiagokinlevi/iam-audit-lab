from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_analyze_policy_writes_output_file(tmp_path: Path) -> None:
    runner = CliRunner()

    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"Version": "2012-10-17", "Statement": []}), encoding="utf-8")

    output_path = tmp_path / "out" / "analysis.json"

    result = runner.invoke(
        cli,
        [
            "analyze-policy",
            "--policy-file",
            str(policy_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.exists()

    rendered = json.loads(output_path.read_text(encoding="utf-8"))
    assert rendered["policy_file"] == str(policy_path)
    assert "findings" in rendered
