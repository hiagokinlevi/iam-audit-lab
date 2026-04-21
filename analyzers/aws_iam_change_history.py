from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


IAM_EVENTS = {
    "CreateRole",
    "DeleteRole",
    "PutRolePolicy",
    "DeleteRolePolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "UpdateAssumeRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "PutGroupPolicy",
    "DeleteGroupPolicy",
    "AddUserToGroup",
    "RemoveUserFromGroup",
}


@dataclass
class IAMChangeRecord:
    event_time: str
    event_name: str
    actor: str
    source_ip: str | None
    user_agent: str | None
    target_type: str
    target_name: str
    policy_arn: str | None
    old_document: dict[str, Any] | None
    new_document: dict[str, Any] | None
    risk_level: str
    risk_reasons: list[str]
    security_impact: str
    raw_event_id: str | None



def _parse_time(s: str | None) -> datetime:
    if not s:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)



def _to_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]



def _normalize_policy_doc(doc: Any) -> dict[str, Any] | None:
    if doc is None:
        return None
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except Exception:
            return None
    if isinstance(doc, dict):
        return doc
    return None



def _statement_iter(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not doc:
        return []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    if isinstance(stmts, list):
        return [s for s in stmts if isinstance(s, dict)]
    return []



def _is_wildcard_permission(stmt: dict[str, Any]) -> bool:
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False
    actions = _to_list(stmt.get("Action")) + _to_list(stmt.get("NotAction"))
    resources = _to_list(stmt.get("Resource")) + _to_list(stmt.get("NotResource"))
    action_wild = any(isinstance(a, str) and (a == "*" or fnmatch(a, "*:*") or a.endswith(":*")) for a in actions)
    resource_wild = any(isinstance(r, str) and r == "*" for r in resources)
    return action_wild and resource_wild



def _escalation_pattern(stmt: dict[str, Any]) -> bool:
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False
    actions = [a.lower() for a in _to_list(stmt.get("Action")) if isinstance(a, str)]
    high_risk = {
        "iam:passrole",
        "iam:attachrolepolicy",
        "iam:putrolepolicy",
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "sts:assumerole",
        "lambda:updatefunctionconfiguration",
        "ec2:runinstances",
    }
    return any(a in high_risk or fnmatch(a, "iam:*") for a in actions)



def _new_external_trust(old_doc: dict[str, Any] | None, new_doc: dict[str, Any] | None) -> list[str]:
    def collect(doc: dict[str, Any] | None) -> set[str]:
        out: set[str] = set()
        for st in _statement_iter(doc):
            if str(st.get("Effect", "")).lower() != "allow":
                continue
            principal = st.get("Principal")
            if isinstance(principal, str):
                out.add(principal)
            elif isinstance(principal, dict):
                for _, v in principal.items():
                    for item in _to_list(v):
                        if isinstance(item, str):
                            out.add(item)
        return out

    old = collect(old_doc)
    new = collect(new_doc)
    added = sorted(new - old)
    risky = [p for p in added if p == "*" or ":root" in p or p.startswith("arn:aws:iam::")]
    return risky



def _extract_actor(event: dict[str, Any]) -> str:
    ui = event.get("userIdentity", {}) or {}
    return ui.get("arn") or ui.get("principalId") or ui.get("userName") or "unknown"



def _extract_target(event_name: str, req: dict[str, Any]) -> tuple[str, str, str | None]:
    if "Role" in event_name:
        return "role", req.get("roleName", "unknown"), req.get("policyArn")
    if "User" in event_name:
        return "user", req.get("userName", "unknown"), req.get("policyArn")
    if "Group" in event_name:
        return "group", req.get("groupName", "unknown"), req.get("policyArn")
    if "Policy" in event_name:
        return "policy", req.get("policyArn", req.get("policyName", "unknown")), req.get("policyArn")
    return "identity", "unknown", req.get("policyArn")



def _load_events(path: str | Path) -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "Records" in raw:
        records = raw.get("Records", [])
    elif isinstance(raw, list):
        records = raw
    else:
        records = []
    return [r for r in records if isinstance(r, dict)]



def audit_cloudtrail_iam_changes(
    cloudtrail_json_path: str | Path,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    events = _load_events(cloudtrail_json_path)
    st = _parse_time(start_time)
    et = _parse_time(end_time) if end_time else datetime.max.replace(tzinfo=timezone.utc)

    timeline: list[IAMChangeRecord] = []

    for e in sorted(events, key=lambda x: _parse_time(x.get("eventTime"))):
        event_name = e.get("eventName")
        if event_name not in IAM_EVENTS:
            continue

        t = _parse_time(e.get("eventTime"))
        if t < st or t > et:
            continue

        req = e.get("requestParameters", {}) or {}
        actor = _extract_actor(e)
        source_ip = e.get("sourceIPAddress")
        user_agent = e.get("userAgent")
        target_type, target_name, policy_arn = _extract_target(event_name, req)

        old_doc = None
        new_doc = None

        if event_name in {"PutRolePolicy", "PutUserPolicy", "PutGroupPolicy", "CreatePolicy", "CreatePolicyVersion"}:
            new_doc = _normalize_policy_doc(req.get("policyDocument"))
        if event_name == "UpdateAssumeRolePolicy":
            new_doc = _normalize_policy_doc(req.get("policyDocument"))

        reasons: list[str] = []
        risk = "low"

        if new_doc:
            if any(_is_wildcard_permission(s) for s in _statement_iter(new_doc)):
                reasons.append("Introduces wildcard allow permissions on wildcard resources")
            if any(_escalation_pattern(s) for s in _statement_iter(new_doc)):
                reasons.append("Introduces potential privilege-escalation actions")

        if event_name == "UpdateAssumeRolePolicy":
            # CloudTrail does not provide old trust doc directly in request; treat added risky principals in new doc as risky.
            added_trust = _new_external_trust(old_doc, new_doc)
            if added_trust:
                reasons.append(f"New trusted principals added: {', '.join(added_trust[:5])}")

        if event_name in {"AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy"}:
            if isinstance(policy_arn, str) and policy_arn.endswith(":policy/AdministratorAccess"):
                reasons.append("AdministratorAccess policy attached")

        if reasons:
            risk = "high"
        elif event_name in {"CreateRole", "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion"}:
            risk = "medium"

        impact = (
            "Potential privilege expansion or trust boundary weakening"
            if risk == "high"
            else "IAM configuration changed"
        )

        timeline.append(
            IAMChangeRecord(
                event_time=e.get("eventTime", ""),
                event_name=event_name,
                actor=actor,
                source_ip=source_ip,
                user_agent=user_agent,
                target_type=target_type,
                target_name=target_name,
                policy_arn=policy_arn,
                old_document=old_doc,
                new_document=new_doc,
                risk_level=risk,
                risk_reasons=reasons,
                security_impact=impact,
                raw_event_id=e.get("eventID"),
            )
        )

    summary = {
        "total_events": len(timeline),
        "high_risk": sum(1 for x in timeline if x.risk_level == "high"),
        "medium_risk": sum(1 for x in timeline if x.risk_level == "medium"),
        "low_risk": sum(1 for x in timeline if x.risk_level == "low"),
    }

    return {
        "summary": summary,
        "changes": [asdict(x) for x in timeline],
    }
