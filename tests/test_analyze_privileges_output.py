from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.commands import cli


def test_analyze_privileges_writes_output_file_with_same_json_as_stdout(tmp_path: Path) -> None:
    input_file = tmp_path / "identities.json"
    input_file.write_text("[]", encoding="utf-8")

    output_file = tmp_path / "out" / "findings.json"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "analyze-privileges",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_file.exists()

    stdout_json = json.loads(result.output)
    file_json = json.loads(output_file.read_text(encoding="utf-8"))
    assert file_json == stdout_json
