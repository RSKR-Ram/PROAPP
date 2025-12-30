from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy import select

from models import (
    AuditLog,
    HoldLog,
    IdCounter,
    JoinLog,
    Permission,
    RejectionLog,
    Requirement,
    RequirementHistory,
)
from utils import ApiError, AuthContext, iso_utc_now, new_log_id, normalize_role, safe_json_string


def append_audit(
    db,
    *,
    entityType: str,
    entityId: str,
    action: str,
    stageTag: str,
    actor: AuthContext | None,
    fromState: str = "",
    toState: str = "",
    remark: str = "",
    meta: Any = None,
    at: Optional[str] = None,
) -> None:
    if meta is None:
        meta_json = "{}"
    elif isinstance(meta, str):
        meta_json = meta
    else:
        meta_json = safe_json_string(meta, "{}")

    db.add(
        AuditLog(
            logId=new_log_id(),
            entityType=str(entityType or ""),
            entityId=str(entityId or ""),
            action=str(action or "").upper(),
            fromState=str(fromState or ""),
            toState=str(toState or ""),
            stageTag=str(stageTag or ""),
            remark=str(remark or ""),
            actorUserId=str(actor.userId if actor else "PUBLIC"),
            actorRole=str(actor.role if actor else "PUBLIC"),
            at=str(at or iso_utc_now()),
            metaJson=meta_json,
        )
    )


def append_requirement_history(
    db,
    *,
    requirementId: str,
    fromStatus: str,
    toStatus: str,
    stageTag: str,
    remark: str,
    actor: AuthContext,
    meta: Any,
) -> None:
    if meta is None:
        meta_json = ""
    else:
        meta_json = safe_json_string(meta, "{}")

    db.add(
        RequirementHistory(
            historyId="RH-" + new_log_id().replace("LOG-", ""),
            requirementId=requirementId,
            fromStatus=str(fromStatus or ""),
            toStatus=str(toStatus or ""),
            stageTag=str(stageTag or ""),
            remark=str(remark or ""),
            actorUserId=str(actor.userId or ""),
            actorRole=str(actor.role or ""),
            at=iso_utc_now(),
            metaJson=meta_json,
        )
    )


def append_join_log(db, *, candidateId: str, requirementId: str, action: str, stageTag: str, remark: str, actor: AuthContext):
    db.add(
        JoinLog(
            logId=new_log_id(),
            candidateId=candidateId,
            requirementId=requirementId,
            action=str(action or ""),
            stageTag=str(stageTag or ""),
            remark=str(remark or ""),
            actorUserId=str(actor.userId or ""),
            actorRole=str(actor.role or ""),
            at=iso_utc_now(),
        )
    )


def append_hold_log(
    db,
    *,
    candidateId: str,
    requirementId: str,
    action: str,
    stageTag: str,
    remark: str,
    actor: AuthContext,
    holdUntil: str,
):
    db.add(
        HoldLog(
            logId=new_log_id(),
            candidateId=candidateId,
            requirementId=requirementId,
            action=str(action or ""),
            holdUntil=str(holdUntil or ""),
            stageTag=str(stageTag or ""),
            remark=str(remark or ""),
            actorUserId=str(actor.userId or ""),
            actorRole=str(actor.role or ""),
            at=iso_utc_now(),
        )
    )


def append_rejection_log(
    db,
    *,
    candidateId: str,
    requirementId: str,
    stageTag: str,
    remark: str,
    actor: AuthContext | None,
    reasonCode: str = "",
):
    if actor and actor.userId and actor.role and actor.role != "SYSTEM":
        rejection_type = "MANUAL"
        auto_code = ""
        actor_user = actor.userId
        actor_role = actor.role
    else:
        rejection_type = "AUTO"
        auto_code = str(reasonCode or "SYSTEM").strip() or "SYSTEM"
        actor_user = "SYSTEM"
        actor_role = "SYSTEM"

    db.add(
        RejectionLog(
            logId=new_log_id(),
            candidateId=candidateId,
            requirementId=requirementId,
            rejectionType=rejection_type,
            autoRejectCode=auto_code,
            stageTag=str(stageTag or ""),
            remark=str(remark or ""),
            actorUserId=str(actor_user),
            actorRole=str(actor_role),
            at=iso_utc_now(),
        )
    )


def _id_counter_next(db, key: str, initial: int) -> int:
    key_u = str(key or "").strip()
    if not key_u:
        raise ApiError("INTERNAL", "Missing id counter key")

    row = (
        db.execute(select(IdCounter).where(IdCounter.key == key_u).with_for_update(of=IdCounter))
        .scalars()
        .first()
    )
    if row:
        n = int(row.nextValue or 1)
        row.nextValue = n + 1
        return n

    # First use: seed counter based on the current max in the table.
    # NOTE: SessionLocal is configured with autoflush=False; explicitly flush this insert
    # so subsequent reads in the same transaction see it (bulk operations call this many times).
    counter = IdCounter(key=key_u, nextValue=int(initial) + 1)
    db.add(counter)
    db.flush([counter])
    return int(initial)


def next_prefixed_id(db, *, counter_key: str, prefix: str, pad: int, existing_ids: list[str]) -> str:
    max_num = 0
    for v in existing_ids:
        s = str(v or "")
        if not s.startswith(prefix):
            continue
        try:
            n = int(s[len(prefix) :])
        except Exception:
            continue
        if n > max_num:
            max_num = n

    next_num = _id_counter_next(db, counter_key, max_num + 1)
    return f"{prefix}{str(next_num).zfill(pad)}"


def require_requirement(db, requirement_id: str) -> Requirement:
    req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")
    return req


def get_permission_rule(db, permType: str, permKey: str) -> Optional[dict[str, Any]]:
    permTypeU = str(permType or "").upper().strip()
    permKeyU = str(permKey or "").upper().strip()
    if not permTypeU or not permKeyU:
        return None
    row = (
        db.execute(select(Permission).where(Permission.permType == permTypeU).where(Permission.permKey == permKeyU))
        .scalars()
        .first()
    )
    if not row:
        return None
    roles = [normalize_role(x) for x in str(row.rolesCsv or "").split(",")]
    roles = [r for r in roles if r]
    return {"enabled": bool(row.enabled), "roles": roles, "rolesCsv": str(row.rolesCsv or "")}
