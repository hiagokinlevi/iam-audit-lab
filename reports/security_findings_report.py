from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
import json


def _to_dict(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "model_dump"):
        return obj.model_dump()  # pydantic v2
    if hasattr(obj, "dict"):
        return obj.dict()  # pydantic v1 fallback
    return vars(obj)


def _normalize_finding(finding: Any) -> dict[str, Any]:
    f = _to_dict(finding)
    risk = f.get("risk_score", 0)
    if isinstance(risk, dict):
        risk = risk.get("score", 0)
    try:
        risk_val = float(risk)
    except Exception:
        risk_val = 0.0

    return {
        "id": f.get("id") or f.get("finding_id") or "unknown-finding",
        "title": f.get("title") or f.get("name") or "Untitled finding",
        "description": f.get("description") or "",
        "provider": f.get("provider") or "unknown",
        "severity": (f.get("severity") or "unknown").lower(),
        "risk_score": risk_val,
        "affected_identities": f.get("affected_identities") or f.get("identities") or [],
        "recommendation": f.get("recommendation") or "Review least-privilege and remediate access.",
        "raw": f,
    }


def _normalize_identity(identity: Any) -> dict[str, Any]:
    i = _to_dict(identity)
    return {
        "id": i.get("id") or i.get("principal_id") or i.get("name") or "unknown-identity",
        "name": i.get("name") or i.get("display_name") or i.get("email") or "unknown",
        "provider": i.get("provider") or "unknown",
        "type": i.get("type") or i.get("identity_type") or "unknown",
        "raw": i,
    }


def _risk_bucket(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def build_security_findings_report(
    findings: list[Any],
    identities: list[Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    normalized_findings = [_normalize_finding(f) for f in findings]
    normalized_identities = [_normalize_identity(i) for i in (identities or [])]

    by_severity: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    affected_identity_ids: set[str] = set()
    total_risk = 0.0

    for f in normalized_findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        prov = f["provider"]
        by_provider[prov] = by_provider.get(prov, 0) + 1
        total_risk += f["risk_score"]
        for ident in f["affected_identities"]:
            if isinstance(ident, str):
                affected_identity_ids.add(ident)
            elif isinstance(ident, dict):
                ident_id = ident.get("id") or ident.get("name")
                if ident_id:
                    affected_identity_ids.add(str(ident_id))

    avg_risk = (total_risk / len(normalized_findings)) if normalized_findings else 0.0

    report = {
        "schema_version": "1.0",
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(normalized_findings),
            "total_identities": len(normalized_identities),
            "affected_identities": len(affected_identity_ids),
            "average_risk_score": round(avg_risk, 2),
            "overall_risk": _risk_bucket(avg_risk),
            "findings_by_severity": by_severity,
            "findings_by_provider": by_provider,
        },
        "findings": [
            {
                "id": f["id"],
                "title": f["title"],
                "description": f["description"],
                "provider": f["provider"],
                "severity": f["severity"],
                "risk_score": f["risk_score"],
                "affected_identities": f["affected_identities"],
                "recommendation": f["recommendation"],
            }
            for f in normalized_findings
        ],
        "identities": normalized_identities,
        "recommended_actions": [
            {
                "finding_id": f["id"],
                "title": f["title"],
                "provider": f["provider"],
                "risk_score": f["risk_score"],
                "action": f["recommendation"],
            }
            for f in normalized_findings
        ],
    }

    return report


def render_security_findings_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(str(f.get('id', '')))}</td>"
            f"<td>{escape(str(f.get('provider', '')))}</td>"
            f"<td>{escape(str(f.get('severity', '')))}</td>"
            f"<td>{escape(str(f.get('risk_score', '')))}</td>"
            f"<td>{escape(str(f.get('title', '')))}</td>"
            f"<td>{escape(str(f.get('recommendation', '')))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Security Findings Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    .meta {{ color: #555; margin-bottom: 1rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 12px; }}
    .label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
    .value {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f7f7f7; }}
  </style>
</head>
<body>
  <h1>Security Findings Report</h1>
  <div class=\"meta\">Generated at: {escape(str(report.get('generated_at', '')))}</div>

  <div class=\"grid\">
    <div class=\"card\"><div class=\"label\">Total Findings</div><div class=\"value\">{summary.get('total_findings', 0)}</div></div>
    <div class=\"card\"><div class=\"label\">Affected Identities</div><div class=\"value\">{summary.get('affected_identities', 0)}</div></div>
    <div class=\"card\"><div class=\"label\">Average Risk Score</div><div class=\"value\">{summary.get('average_risk_score', 0)}</div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Provider</th><th>Severity</th><th>Risk</th><th>Title</th><th>Recommended Action</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""


def write_security_findings_report(
    findings: list[Any],
    identities: list[Any] | None,
    json_output_path: str | Path,
    html_output_path: str | Path,
) -> dict[str, Any]:
    report = build_security_findings_report(findings=findings, identities=identities)

    json_path = Path(json_output_path)
    html_path = Path(html_output_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_path.write_text(render_security_findings_html(report), encoding="utf-8")
    return report
