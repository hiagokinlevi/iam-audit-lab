import json
from pathlib import Path

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def _record(provider: str, name: str, permissions: list[str]):
    return {
        "provider": provider,
        "account_id": f"acct-{provider}",
        "principal_id": f"{provider}-{name}",
        "principal_name": name,
        "principal_type": "user",
        "roles": [],
        "permissions": permissions,
        "mfa_enabled": True,
        "is_active": True,
    }


def test_analyze_privileges_provider_filter_and_empty_result(tmp_path: Path):
    runner = CliRunner()
    input_file = tmp_path / "identities.json"
    output_file = tmp_path / "findings.json"

    identities = [
        _record("aws", "admin-user", ["*"]),
        _record("azure", "reader-user", ["read:all"]),
    ]
    input_file.write_text(json.dumps(identities), encoding="utf-8")

    result = runner.invoke(
        cli,
        [
            "analyze-privileges",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--provider",
            "aws",
        ],
    )
    assert result.exit_code == 0, result.output

    findings = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(findings, list)
    assert len(findings) >= 1
    assert all(f.get("provider") == "aws" for f in findings if isinstance(f, dict) and "provider" in f)

    empty_output = tmp_path / "empty.json"
    result_empty = runner.invoke(
        cli,
        [
            "analyze-privileges",
            "--input",
            str(input_file),
            "--output",
            str(empty_output),
            "--provider",
            "gcp",
        ],
    )
    assert result_empty.exit_code == 0, result_empty.output
    assert json.loads(empty_output.read_text(encoding="utf-8")) == []
