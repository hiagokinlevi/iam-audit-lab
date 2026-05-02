import json

from click.testing import CliRunner

from cli.main import cli


def _write_input(tmp_path, findings):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return p


def test_analyze_privileges_default_behavior_no_fail(tmp_path):
    input_file = _write_input(
        tmp_path,
        [
            {"id": "f1", "severity": "high"},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze-privileges", "--input", str(input_file)])

    assert result.exit_code == 0


def test_analyze_privileges_fails_when_threshold_met(tmp_path):
    input_file = _write_input(
        tmp_path,
        [
            {"id": "f1", "severity": "medium"},
            {"id": "f2", "severity": "critical"},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["analyze-privileges", "--input", str(input_file), "--fail-on-severity", "HIGH"],
    )

    assert result.exit_code != 0


def test_analyze_privileges_passes_when_no_finding_meets_threshold(tmp_path):
    input_file = _write_input(
        tmp_path,
        [
            {"id": "f1", "severity": "low"},
            {"id": "f2", "severity": "medium"},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["analyze-privileges", "--input", str(input_file), "--fail-on-severity", "critical"],
    )

    assert result.exit_code == 0
