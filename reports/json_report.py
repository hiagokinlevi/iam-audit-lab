from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def _to_serializable(item: Any) -> dict[str, Any]:
    if hasattr(item, "model_dump"):
        return item.model_dump(mode="json")
    if hasattr(item, "dict"):
        return item.dict()
    if isinstance(item, dict):
        return item
    raise TypeError(f"Unsupported item type for JSON export: {type(item)!r}")


def export_json_report(
    findings: Iterable[Any],
    identities: Iterable[Any],
    output_path: str | Path = "iam_audit_report.json",
) -> Path:
    payload = {
        "findings": [_to_serializable(f) for f in findings],
        "identities": [_to_serializable(i) for i in identities],
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
