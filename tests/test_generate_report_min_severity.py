import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_generate_report_filters_by_min_severity_json(tmp_path):
    in_file = tmp_path / "findings.json"
    out_file = tmp_path / "report.json"

    payload = {
        "findings": [
            {"title": "Low finding", "severity": "low"},
            {"title": "Medium finding", "severity": "medium"},
            {"title": "High finding", "severity": "high"},
            {"title": "Critical finding", "severity": "critical"},
        ]
    }

    in_file.write_text(json.dumps(payload), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "generate-report",
            "--input",
            str(in_file),
            "--output",
            str(out_file),
            "--format",
            "json",
            "--min-severity",
            "high",
        ],
    )

    assert result.exit_code == 0, result.output

    out = json.loads(out_file.read_text(encoding="utf-8"))
    titles = [f["title"] for f in out["findings"]]
    assert titles == ["High finding", "Critical finding"]
