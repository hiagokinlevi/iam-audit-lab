from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from iam_audit_lab_cli.cli import cli


def _identity(identity_id: str, last_seen_days_ago: int) -> dict:
    return {
        "provider": "aws",
        "identity_id": identity_id,
        "display_name": identity_id,
        "identity_type": "user",
        "email": None,
        "roles": [],
        "is_privileged": False,
        "mfa_enabled": False,
        "last_seen": (datetime.now(timezone.utc) - timedelta(days=last_seen_days_ago)).isoformat(),
        "metadata": {},
    }


def test_analyze_inactive_min_last_seen_days_filters_output(tmp_path):
    runner = CliRunner()

    identities = [
        _identity("u-95", 95),
        _identity("u-120", 120),
    ]

    input_path = tmp_path / "identities.json"
    input_path.write_text(json.dumps(identities), encoding="utf-8")

    unfiltered_out = tmp_path / "inactive_unfiltered.json"
    filtered_out = tmp_path / "inactive_filtered.json"

    res_unfiltered = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_path),
            "--days",
            "90",
            "--output",
            str(unfiltered_out),
        ],
    )
    assert res_unfiltered.exit_code == 0, res_unfiltered.output

    res_filtered = runner.invoke(
        cli,
        [
            "analyze-inactive",
            "--input",
            str(input_path),
            "--days",
            "90",
            "--min-last-seen-days",
            "110",
            "--output",
            str(filtered_out),
        ],
    )
    assert res_filtered.exit_code == 0, res_filtered.output

    unfiltered = json.loads(unfiltered_out.read_text(encoding="utf-8"))
    filtered = json.loads(filtered_out.read_text(encoding="utf-8"))

    assert len(unfiltered) == 2
    assert len(filtered) == 1
