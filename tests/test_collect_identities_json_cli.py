from __future__ import annotations

import json

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


class _Record:
    def __init__(self, **kwargs):
        self._data = kwargs

    def model_dump(self, mode: str = "json"):
        return dict(self._data)


def test_collect_identities_json_output_shape_and_order(monkeypatch):
    runner = CliRunner()

    fake_records = [
        _Record(provider="aws", identity_type="role", account_id="222", principal_name="z-role", id="2"),
        _Record(provider="aws", identity_type="user", account_id="111", principal_name="a-user", id="1"),
    ]

    def _fake_collect_identities(provider: str):
        return fake_records

    monkeypatch.setattr("iam_audit_lab_cli.cli.collect_identities", _fake_collect_identities)

    result = runner.invoke(cli, ["collect-identities", "--provider", "aws", "--json"])

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert set(parsed[0].keys()) >= {"provider", "identity_type", "account_id", "principal_name", "id"}
    assert [r["principal_name"] for r in parsed] == ["z-role", "a-user"] or [r["principal_name"] for r in parsed] == ["a-user", "z-role"]

    expected_sorted = sorted(
        parsed,
        key=lambda r: (r["provider"], r["identity_type"], r["account_id"], r["principal_name"], r["id"]),
    )
    assert parsed == expected_sorted
