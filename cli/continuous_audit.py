from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click


DEFAULT_INTERVAL_SECONDS = 3600
DEFAULT_HISTORY_DIR = ".iam-audit-history"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_key(finding: dict[str, Any]) -> str:
    """
    Build a stable key for finding diffing across runs.
    Falls back safely if fields vary by analyzer output shape.
    """
    provider = finding.get("provider", "unknown")
    identity = finding.get("identity", finding.get("principal", "unknown"))
    finding_type = finding.get("type", finding.get("category", "unknown"))
    resource = finding.get("resource", "")
    permission = finding.get("permission", finding.get("action", ""))
    return "|".join([str(provider), str(identity), str(finding_type), str(resource), str(permission)])


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _extract_excessive_findings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Tolerant extraction for repositories where output envelope may differ.
    Expected common shape: {"findings": [...]}.
    """
    findings = scan.get("findings", [])
    if not isinstance(findings, list):
        return []

    excessive: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        f_type = str(f.get("type", f.get("category", ""))).lower()
        title = str(f.get("title", "")).lower()
        if "excess" in f_type or "privilege" in f_type or "admin" in title or "wildcard" in title:
            excessive.append(f)
    return excessive


def _compute_new_findings(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prev_keys = {_finding_key(f) for f in previous}
    return [f for f in current if _finding_key(f) not in prev_keys]


@click.command("continuous-audit")
@click.option("--input", "input_file", type=click.Path(path_type=Path, exists=True), required=True, help="Path to latest scan JSON.")
@click.option("--interval-seconds", type=int, default=DEFAULT_INTERVAL_SECONDS, show_default=True, help="Seconds between audit checks.")
@click.option("--history-dir", type=click.Path(path_type=Path), default=Path(DEFAULT_HISTORY_DIR), show_default=True, help="Directory for persisted audit snapshots.")
@click.option("--iterations", type=int, default=1, show_default=True, help="Number of cycles to run (use 0 for infinite).")
def continuous_audit(input_file: Path, interval_seconds: int, history_dir: Path, iterations: int) -> None:
    """
    Scheduled audit mode:
    - reads scan JSON periodically
    - compares excessive-permission findings with previous snapshot
    - highlights newly introduced excessive permissions
    """
    snapshot_path = history_dir / "latest_snapshot.json"

    run = 0
    while True:
        run += 1
        scan = _load_json(input_file)
        prev_snapshot = _load_json(snapshot_path)

        current_excessive = _extract_excessive_findings(scan)
        previous_excessive = _extract_excessive_findings(prev_snapshot)
        new_findings = _compute_new_findings(previous_excessive, current_excessive)

        click.echo(f"[{_utc_now_iso()}] Continuous audit cycle #{run}")
        click.echo(f"Current excessive findings: {len(current_excessive)}")
        click.echo(f"Newly introduced excessive findings: {len(new_findings)}")

        if new_findings:
            click.echo("--- New excessive permissions detected ---")
            for idx, finding in enumerate(new_findings, start=1):
                title = finding.get("title", finding.get("type", "unknown-finding"))
                ident = finding.get("identity", finding.get("principal", "unknown-identity"))
                provider = finding.get("provider", "unknown-provider")
                click.echo(f"{idx}. [{provider}] {ident} -> {title}")

        # Save latest scan as baseline for next cycle
        _save_json(snapshot_path, scan)

        if iterations > 0 and run >= iterations:
            break

        time.sleep(max(1, interval_seconds))
