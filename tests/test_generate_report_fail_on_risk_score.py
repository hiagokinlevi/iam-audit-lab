from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_generate_report_passes_when_below_threshold(tmp_path):
    findings_path = tmp_path / "findings.json"
    output_path = tmp_path / "report.json"

    _write_json(
        findings_path,
        [
            {"id": "f1", "risk": {"score": 10}},
            {"id": "f2", "risk": {"score": 20}},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "generate-report",
            "--findings",
            str(findings_path),
            "--output",
            str(output_path),
            "--fail-on-risk-score",
            "50",
        ],
    )

    assert result.exit_code == 0
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["summary"]["aggregate_risk_score"] == 30.0


def test_generate_report_fails_when_meets_threshold(tmp_path):
    findings_path = tmp_path / "findings.json"
    output_path = tmp_path / "report.json"

    _write_json(
        findings_path,
        [
            {"id": "f1", "risk": {"score": 25}},
            {"id": "f2", "risk": {"score": 25}},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "generate-report",
            "--findings",
            str(findings_path),
            "--output",
            str(output_path),
            "--fail-on-risk-score",
            "50",
        ],
    )

    assert result.exit_code != 0
    assert "Risk threshold exceeded" in result.output


def test_generate_report_rejects_out_of_range_threshold(tmp_path):
    findings_path = tmp_path / "findings.json"
    output_path = tmp_path / "report.json"
    _write_json(findings_path, [])

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "generate-report",
            "--findings",
            str(findings_path),
            "--output",
            str(output_path),
            "--fail-on-risk-score",
            "101",
        ],
    )

    assert result.exit_code != 0
    assert "0<=x<=100" in result.output
