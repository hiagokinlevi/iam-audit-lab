from __future__ import annotations

import json

from click.testing import CliRunner

from cli.main import cli


def test_analyze_privileges_rejects_non_array_identities_payload() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("identities.json", "w", encoding="utf-8") as handle:
            json.dump({"identity_name": "alice"}, handle)

        result = runner.invoke(
            cli,
            [
                "analyze-privileges",
                "--identities-file",
                "identities.json",
            ],
        )

    assert result.exit_code != 0
    assert "Identities file must contain a top-level JSON array" in result.output
