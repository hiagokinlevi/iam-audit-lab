from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.main import cli


def test_collect_identities_single_provider_aws(monkeypatch, tmp_path):
    calls = []

    def fake_aws(profile=None):
        calls.append("aws")
        return []

    def fake_azure(tenant_id=None):
        calls.append("azure")
        return []

    def fake_gcp(project_id=None):
        calls.append("gcp")
        return []

    monkeypatch.setattr("iam_audit_lab_cli.main.collect_aws_identities", fake_aws)
    monkeypatch.setattr("iam_audit_lab_cli.main.collect_azure_identities", fake_azure)
    monkeypatch.setattr("iam_audit_lab_cli.main.collect_gcp_identities", fake_gcp)

    out = tmp_path / "ids.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["collect-identities", "--provider", "aws", "--output", str(out)])

    assert result.exit_code == 0
    assert calls == ["aws"]
    assert json.loads(out.read_text()) == []


def test_collect_identities_multi_provider_aws_gcp(monkeypatch, tmp_path):
    calls = []

    def fake_aws(profile=None):
        calls.append("aws")
        return []

    def fake_azure(tenant_id=None):
        calls.append("azure")
        return []

    def fake_gcp(project_id=None):
        calls.append("gcp")
        return []

    monkeypatch.setattr("iam_audit_lab_cli.main.collect_aws_identities", fake_aws)
    monkeypatch.setattr("iam_audit_lab_cli.main.collect_azure_identities", fake_azure)
    monkeypatch.setattr("iam_audit_lab_cli.main.collect_gcp_identities", fake_gcp)

    out = tmp_path / "ids.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "collect-identities",
            "--provider",
            "aws",
            "--provider",
            "gcp",
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert calls == ["aws", "gcp"]
    assert json.loads(out.read_text()) == []
