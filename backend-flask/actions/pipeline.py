from __future__ import annotations

# NOTE: This file is generated in multiple small patches to avoid tooling limits.
import json
import os
import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from actions.candidate_repo import (
    find_candidate,
    is_test_continued,
    reject_candidate_with_meta,
    upsert_test_decision,
    update_candidate,
)
from actions.helpers import append_audit, append_join_log, append_rejection_log, append_requirement_history
from actions.jobposting import assert_job_posting_complete
from actions.training import training_summary
from models import Candidate, Employee, OnlineTest, Requirement, Setting
from utils import ApiError, AuthContext, decode_base64_to_bytes, iso_utc_now, parse_datetime_maybe, sanitize_filename, to_iso_utc


def _get_setting_number(db, key: str, fallback: float) -> float:
    k = str(key or "").strip()
    if not k:
        return float(fallback)
    row = db.execute(select(Setting).where(Setting.key == k)).scalar_one_or_none()
    if not row:
        return float(fallback)
    raw = getattr(row, "value", "")
    try:
        s = str(raw or "").strip()
        if not s:
            return float(fallback)
        n = float(s)
        if n != n:  # NaN
            return float(fallback)
        return n
    except Exception:
        return float(fallback)


def _parse_ymd(date_iso: str) -> Optional[date]:
    s = str(date_iso or "").strip()
    if not s:
        return None
    parts = s.split("-")
    if len(parts) != 3:
        return None
    try:
        y = int(parts[0])
        m = int(parts[1])
        d = int(parts[2])
        return date(y, m, d)
    except Exception:
        return None


def _get_requirements_map(db) -> dict[str, dict[str, str]]:
    rows = db.execute(select(Requirement.requirementId, Requirement.jobRole, Requirement.jobTitle)).all()
    return {str(rid): {"jobRole": jr or "", "jobTitle": jt or ""} for rid, jr, jt in rows if str(rid or "").strip()}


def _normalize_job_role(s: Any) -> str:
    return str(s or "").strip().upper()


def _allowed_tech_tests_for_role(job_role: Any) -> list[str]:
    r = _normalize_job_role(job_role)
    if "ACCOUNTS" in r:
        return ["Tally", "Excel"]
    if r == "CRM" or r == "CCE" or r == "PC" or "CRM" in r or "CCE" in r or "PC" in r:
        return ["Excel", "Voice"]
    return ["Excel"]


def _parse_json_list(raw: Any) -> list[Any]:
    try:
        s = str(raw or "").strip()
        if not s:
            return []
        obj = json.loads(s)
        return obj if isinstance(obj, list) else []
    except Exception:
        return []


def _normalize_number(value: Any) -> Optional[float]:
    if value is None:
        return None
    s = str(value or "").strip()
    if not s:
        return None
    s = s.replace(",", "")
    try:
        n = float(s)
    except Exception:
        return None
    if n != n:  # NaN
        return None
    return n


def _make_question_set() -> list[dict[str, Any]]:
    q: list[dict[str, Any]] = []

    percents = [10, 20, 25, 30, 40, 50, 60, 75]
    p = random.choice(percents)
    base = random.randint(2, 10) * 20  # 40..200 step 20
    ans_p = (p * base) / 100
    q.append({"id": "D", "type": "number", "weight": 3, "prompt": f"What is {p}% of {base}?", "correct": ans_p})

    fracs = [{"a": 1, "b": 2}, {"a": 1, "b": 4}, {"a": 3, "b": 4}, {"a": 2, "b": 3}, {"a": 3, "b": 5}]
    f = random.choice(fracs)
    n_base = random.randint(2, 10) * int(f["b"])
    ans_f = (int(f["a"]) * n_base) / int(f["b"])
    q.append(
        {
            "id": "E",
            "type": "number",
            "weight": 3,
            "prompt": f"What is {int(f['a'])}/{int(f['b'])} of {n_base}?",
            "correct": ans_f,
        }
    )

    unit_cases = [
        {"from": "km", "to": "m", "mul": 1000},
        {"from": "m", "to": "cm", "mul": 100},
        {"from": "kg", "to": "g", "mul": 1000},
        {"from": "g", "to": "kg", "mul": 1 / 1000},
    ]
    uc = random.choice(unit_cases)
    amount = random.randint(1, 9) * (500 if uc["from"] == "g" else 2)
    if uc["from"] == "g":
        amount = random.randint(1, 9) * 500
    ans_u = amount * float(uc["mul"])
    q.append(
        {
            "id": "F",
            "type": "number",
            "weight": 2,
            "prompt": f"Convert {amount} {uc['from']} to {uc['to']}.",
            "correct": ans_u,
        }
    )

    per_item = random.randint(2, 10) * 5  # 10..55 step 5
    count = random.randint(3, 9)
    total = per_item * count
    q.append(
        {
            "id": "G",
            "type": "number",
            "weight": 2,
            "prompt": f"If {count} items cost {total}, what is the cost of 1 item?",
            "correct": per_item,
        }
    )

    return q


def _is_expired(expires_at: Any, *, cfg) -> bool:
    if not expires_at:
        return False
    dt = parse_datetime_maybe(expires_at, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        return False
    return dt < datetime.now(timezone.utc)


@dataclass(frozen=True)
class _PublicTokenValidation:
    valid: bool
    reason: str = ""
    expiresAt: str = ""
    candidateId: str = ""
    requirementId: str = ""
    submitted: bool = False


def _public_validate_test_token(db, token: str, cfg) -> _PublicTokenValidation:
    tok = str(token or "").strip()
    if not tok:
        return _PublicTokenValidation(valid=False, reason="MISSING_TOKEN")

    cand = db.execute(select(Candidate).where(Candidate.testToken == tok)).scalar_one_or_none()
    if not cand:
        return _PublicTokenValidation(valid=False, reason="INVALID_TOKEN")

    expires_at = str(getattr(cand, "testTokenExpiresAt", "") or "")
    if expires_at and _is_expired(expires_at, cfg=cfg):
        return _PublicTokenValidation(
            valid=False,
            reason="EXPIRED",
            expiresAt=expires_at,
            candidateId=str(cand.candidateId or ""),
            requirementId=str(cand.requirementId or ""),
        )

    row = db.execute(select(OnlineTest).where(OnlineTest.token == tok)).scalar_one_or_none()
    submitted = False
    if row:
        submitted = str(getattr(row, "status", "") or "").upper() == "SUBMITTED"

    return _PublicTokenValidation(
        valid=True,
        expiresAt=expires_at or "",
        candidateId=str(cand.candidateId or ""),
        requirementId=str(cand.requirementId or ""),
        submitted=submitted,
    )


def hr_walkin_schedule(data, auth: AuthContext | None, db, cfg):
    # Backward-compatible alias. Use WALKIN_SCHEDULE going forward.
    return walkin_schedule(data, auth, db, cfg)


def walkin_schedule(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    walkin_at_iso = str((data or {}).get("walkinAt") or "").strip()
    notes = str((data or {}).get("notes") or "").strip()

    candidate_id = str((data or {}).get("candidateId") or "").strip()
    candidate_ids = (data or {}).get("candidateIds") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not walkin_at_iso:
        raise ApiError("BAD_REQUEST", "Missing walkinAt")

    if candidate_id:
        candidate_ids = [candidate_id]
    if not isinstance(candidate_ids, list) or len(candidate_ids) == 0:
        raise ApiError("BAD_REQUEST", "Missing candidateId(s)")
    if len(candidate_ids) > 50:
        raise ApiError("BAD_REQUEST", "Max 50 candidates")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    dt = parse_datetime_maybe(walkin_at_iso, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid walkinAt")
    walkin_at = to_iso_utc(dt)

    updated: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []

    for i, cid_raw in enumerate(candidate_ids):
        cid = str(cid_raw or "").strip()
        if not cid:
            errors.append({"index": i, "candidateId": "", "message": "Missing candidateId"})
            continue
        try:
            cand = find_candidate(db, candidate_id=cid, requirement_id=requirement_id)
            current_status = str(cand.status or "").upper()
            if current_status not in {"WALKIN_PENDING", "WALKIN_SCHEDULED"}:
                raise ApiError("BAD_REQUEST", "Owner approval required before scheduling walk-in")

            update_candidate(
                db,
                cand=cand,
                patch={"status": "WALKIN_SCHEDULED", "walkinAt": walkin_at, "walkinNotes": notes},
                auth=auth,
            )

            append_audit(
                db,
                entityType="CANDIDATE",
                entityId=cid,
                action="WALKIN_SCHEDULE",
                fromState=current_status,
                toState="WALKIN_SCHEDULED",
                stageTag="HR_WALKIN_SCHEDULE",
                remark=notes,
                actor=auth,
                at=iso_utc_now(),
                meta={"requirementId": requirement_id, "walkinAt": walkin_at},
            )

            updated.append({"candidateId": cid})
        except Exception as e:
            if isinstance(e, ApiError):
                msg = e.message
            else:
                msg = str(e) or "Failed"
            errors.append({"index": i, "candidateId": cid, "message": msg})

    return {"updated": updated, "errors": errors, "walkinAt": walkin_at}


def precall_list(data, auth: AuthContext | None, db, cfg):
    job_role_filter = str((data or {}).get("jobRole") or "").strip()
    date_iso = str((data or {}).get("date") or "").strip()
    count_only = bool((data or {}).get("countOnly"))

    start_utc = None
    end_utc = None
    ymd = _parse_ymd(date_iso) if date_iso else None
    if ymd:
        try:
            tz = ZoneInfo(cfg.APP_TIMEZONE)
        except Exception:
            tz = timezone.utc
        start_local = datetime(ymd.year, ymd.month, ymd.day, 0, 0, 0, tzinfo=tz)
        end_local = datetime(ymd.year, ymd.month, ymd.day, 23, 59, 59, tzinfo=tz)
        start_utc = start_local.astimezone(timezone.utc)
        end_utc = end_local.astimezone(timezone.utc)

    req_map = None
    if not count_only or job_role_filter:
        req_map = _get_requirements_map(db)

    rows = (
        db.execute(select(Candidate).where(func.upper(Candidate.status) == "WALKIN_SCHEDULED").order_by(Candidate.walkinAt))
        .scalars()
        .all()
    )
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        job_role = str(c.jobRole or rm.get("jobRole", "") or "").strip()
        if job_role_filter and job_role != job_role_filter:
            continue

        walkin_at_raw = str(c.walkinAt or "").strip()
        walkin_dt = parse_datetime_maybe(walkin_at_raw, app_timezone=cfg.APP_TIMEZONE) if walkin_at_raw else None
        if start_utc and end_utc and walkin_dt:
            if walkin_dt < start_utc or walkin_dt > end_utc:
                continue

        total += 1
        if count_only:
            continue

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "source": c.source,
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "walkinAt": c.walkinAt or "",
                "walkinNotes": c.walkinNotes or "",
                "notPickCount": int(c.notPickCount or 0),
                "preCallAt": c.preCallAt or "",
                "onlineTestScore": c.onlineTestScore or "",
                "onlineTestResult": c.onlineTestResult or "",
                "onlineTestSubmittedAt": c.onlineTestSubmittedAt or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    def _walkin_sort_key(it: dict[str, Any]) -> datetime:
        dt0 = parse_datetime_maybe(it.get("walkinAt") or "", app_timezone=cfg.APP_TIMEZONE)
        return dt0 or datetime.min.replace(tzinfo=timezone.utc)

    items.sort(key=_walkin_sort_key)
    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def precall_update(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    op = str((data or {}).get("op") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    pre_call_at_iso = str((data or {}).get("preCallAt") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not op:
        raise ApiError("BAD_REQUEST", "Missing op")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "WALKIN_SCHEDULED":
        raise ApiError("BAD_REQUEST", "Candidate not scheduled")

    now = iso_utc_now()

    if op == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        append_rejection_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            stageTag="Reject On Call",
            remark=remark,
            actor=auth,
        )
        update_candidate(db, cand=cand, patch={"status": "REJECTED"}, auth=auth)
        return {"ok": True, "status": "REJECTED"}

    if op == "NOT_PICK":
        existing_count = int(cand.notPickCount or 0)
        if existing_count < 0:
            existing_count = 0
        next_count = existing_count + 1

        update_candidate(db, cand=cand, patch={"notPickCount": next_count}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PRECALL_UPDATE",
            fromState=current_status,
            toState=current_status,
            stageTag="Not Pick",
            remark=str(next_count),
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "notPickCount": next_count},
        )

        threshold = int(_get_setting_number(db, "NOT_PICK_THRESHOLD", 3))
        if next_count >= threshold:
            update_candidate(db, cand=cand, patch={"status": "REJECTED"}, auth=auth)
            append_rejection_log(
                db,
                candidateId=candidate_id,
                requirementId=requirement_id,
                stageTag="Not Pick Auto Reject",
                remark="Threshold reached",
                actor=None,
                reasonCode="NOT_PICK_THRESHOLD",
            )
            return {"ok": True, "status": "REJECTED", "notPickCount": next_count, "autoRejected": True, "threshold": threshold}

        return {"ok": True, "status": current_status, "notPickCount": next_count, "autoRejected": False, "threshold": threshold}

    if op == "CALL_DONE":
        if not pre_call_at_iso:
            raise ApiError("BAD_REQUEST", "Missing preCallAt")
        dt = parse_datetime_maybe(pre_call_at_iso, app_timezone=cfg.APP_TIMEZONE)
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid preCallAt")
        pre_call_at = to_iso_utc(dt)

        update_candidate(db, cand=cand, patch={"preCallAt": pre_call_at}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PRECALL_UPDATE",
            fromState=current_status,
            toState=current_status,
            stageTag="Call Done",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "preCallAt": pre_call_at},
        )
        return {"ok": True, "status": current_status, "preCallAt": pre_call_at}

    raise ApiError("BAD_REQUEST", "Invalid op")


def auto_reject_notpick(data, auth: AuthContext | None, db, cfg):
    threshold = int(_get_setting_number(db, "NOT_PICK_THRESHOLD", 3))
    rows = db.execute(select(Candidate)).scalars().all()
    scanned = len(rows)
    if not rows:
        return {"scanned": 0, "rejected": 0, "threshold": threshold}

    rejected = 0
    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")

    for c in rows:
        if str(c.status or "").upper() != "WALKIN_SCHEDULED":
            continue
        cnt = int(c.notPickCount or 0)
        if cnt < threshold:
            continue
        update_candidate(db, cand=c, patch={"status": "REJECTED"}, auth=system)
        append_rejection_log(
            db,
            candidateId=str(c.candidateId or ""),
            requirementId=str(c.requirementId or ""),
            stageTag="Not Pick Auto Reject",
            remark="Threshold reached",
            actor=None,
            reasonCode="NOT_PICK_THRESHOLD",
        )
        rejected += 1

    return {"scanned": scanned, "rejected": rejected, "threshold": threshold}


def preinterview_status(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    op = str((data or {}).get("op") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    pre_interview_at_iso = str((data or {}).get("preInterviewAt") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not op:
        raise ApiError("BAD_REQUEST", "Missing op")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate already rejected")

    now = iso_utc_now()

    if op == "APPEARED":
        pre_at = str(cand.preCallAt or "").strip()
        if not pre_at:
            raise ApiError("BAD_REQUEST", "Pre-interview datetime not set")
        update_candidate(db, cand=cand, patch={"preInterviewStatus": "APPEARED"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PREINTERVIEW_STATUS",
            fromState=current_status,
            toState=current_status,
            stageTag="PreInterview Appeared",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": current_status, "preInterviewStatus": "APPEARED"}

    if op == "RESCHEDULE":
        if not pre_interview_at_iso:
            raise ApiError("BAD_REQUEST", "Missing preInterviewAt")
        dt = parse_datetime_maybe(pre_interview_at_iso, app_timezone=cfg.APP_TIMEZONE)
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid preInterviewAt")
        pre_interview_at = to_iso_utc(dt)

        update_candidate(db, cand=cand, patch={"preCallAt": pre_interview_at, "preInterviewStatus": "SCHEDULED"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PREINTERVIEW_STATUS",
            fromState=current_status,
            toState=current_status,
            stageTag="PreInterview Reschedule",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "preInterviewAt": pre_interview_at},
        )
        return {"ok": True, "status": current_status, "preInterviewAt": pre_interview_at, "preInterviewStatus": "SCHEDULED"}

    if op == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        append_rejection_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            stageTag="PreInterview Reject",
            remark=remark,
            actor=auth,
        )
        update_candidate(db, cand=cand, patch={"status": "REJECTED"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PREINTERVIEW_STATUS",
            fromState=current_status,
            toState="REJECTED",
            stageTag="PreInterview Reject",
            remark=remark,
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": "REJECTED"}

    raise ApiError("BAD_REQUEST", "Invalid op")


def preinterview_marks_save(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    marks = (data or {}).get("marks") if isinstance(data, dict) else ""

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    current_pi_status = str(cand.preInterviewStatus or "").upper()
    if current_pi_status != "APPEARED":
        raise ApiError("BAD_REQUEST", "Candidate not marked Appeared")

    now = iso_utc_now()
    marks_val = "" if marks is None or marks == "" else str(marks)
    update_candidate(db, cand=cand, patch={"preInterviewMarks": marks_val, "preInterviewMarksAt": now}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="PREINTERVIEW_MARKS_SAVE",
        fromState=current_status,
        toState=current_status,
        stageTag="PreInterview Marks Save",
        remark="" if marks_val == "" else str(marks_val),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )
    return {"ok": True, "status": current_status, "preInterviewMarks": marks_val, "preInterviewMarksAt": now}


def test_link_create(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    marks = getattr(cand, "preInterviewMarks", "")
    if marks is None or str(marks).strip() == "":
        raise ApiError("BAD_REQUEST", "Save marks first")

    submitted_at = str(getattr(cand, "onlineTestSubmittedAt", "") or "").strip()
    if submitted_at:
        raise ApiError("CONFLICT", "Online test already submitted")

    submitted_row = db.execute(
        select(OnlineTest).where(
            OnlineTest.candidateId == str(cand.candidateId or ""),
            OnlineTest.requirementId == str(cand.requirementId or ""),
            func.upper(OnlineTest.status) == "SUBMITTED",
        )
    ).scalar_one_or_none()
    if submitted_row:
        raise ApiError("CONFLICT", "Online test already submitted")

    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    expires_iso = to_iso_utc(now_dt + timedelta(days=1))
    token = "TST-" + os.urandom(16).hex()

    update_candidate(db, cand=cand, patch={"testToken": token, "testTokenExpiresAt": expires_iso}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TEST_LINK_CREATE",
        fromState=current_status,
        toState=current_status,
        stageTag="TEST_LINK_CREATE",
        remark="",
        actor=auth,
        at=now_iso,
        meta={"requirementId": requirement_id, "tokenPrefix": token[:8], "expiresAt": expires_iso},
    )

    return {"ok": True, "token": token, "expiresAt": expires_iso}


def test_token_validate(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    v = _public_validate_test_token(db, token, cfg)
    if not v.valid:
        out = {"valid": False, "reason": v.reason}
        if v.reason == "EXPIRED":
            out.update({"expiresAt": v.expiresAt, "candidateId": v.candidateId, "requirementId": v.requirementId})
        return out

    return {
        "valid": True,
        "expiresAt": v.expiresAt,
        "candidateId": v.candidateId,
        "requirementId": v.requirementId,
        "submitted": bool(v.submitted),
    }


def test_questions_get(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    v = _public_validate_test_token(db, token, cfg)
    if not v.valid:
        raise ApiError("BAD_REQUEST", v.reason)

    cand = db.execute(select(Candidate).where(Candidate.testToken == token)).scalar_one_or_none()
    if not cand:
        raise ApiError("BAD_REQUEST", "INVALID_TOKEN")

    test_row = db.execute(select(OnlineTest).where(OnlineTest.token == token)).scalar_one_or_none()
    if not test_row:
        now = iso_utc_now()
        test_row = OnlineTest(
            testId="TSTROW-" + os.urandom(16).hex(),
            token=token,
            candidateId=str(cand.candidateId or ""),
            requirementId=str(cand.requirementId or ""),
            issuedAt=now,
            expiresAt=str(getattr(cand, "testTokenExpiresAt", "") or ""),
            status="ISSUED",
            fullName="",
            applyingFor="",
            source="",
            questionsJson="",
            answersJson="",
            score=None,
            result="",
            submittedAt="",
            updatedAt=now,
        )
        db.add(test_row)

    if str(getattr(test_row, "status", "") or "").upper() == "SUBMITTED":
        return {"alreadySubmitted": True}

    questions = _parse_json_list(getattr(test_row, "questionsJson", "") or "")
    if not questions:
        questions = _make_question_set()
        test_row.questionsJson = json.dumps(questions)
        test_row.updatedAt = iso_utc_now()

    public_questions: list[dict[str, Any]] = []
    for x in questions:
        if not isinstance(x, dict):
            continue
        public_questions.append(
            {
                "id": x.get("id"),
                "prompt": x.get("prompt"),
                "type": x.get("type") or "text",
                "weight": int(_normalize_number(x.get("weight")) or 1),
            }
        )

    return {
        "expiresAt": v.expiresAt,
        "candidateId": v.candidateId,
        "requirementId": v.requirementId,
        "fixed": {"fullName": "", "applyingFor": "", "source": ""},
        "questions": public_questions,
    }


def test_submit_public(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    if not token:
        raise ApiError("BAD_REQUEST", "MISSING_TOKEN")

    cand = db.execute(select(Candidate).where(Candidate.testToken == token)).scalar_one_or_none()
    if not cand:
        raise ApiError("BAD_REQUEST", "INVALID_TOKEN")

    expires_at = str(getattr(cand, "testTokenExpiresAt", "") or "")
    if expires_at and _is_expired(expires_at, cfg=cfg):
        raise ApiError("BAD_REQUEST", "EXPIRED")

    test_row = db.execute(select(OnlineTest).where(OnlineTest.token == token)).scalar_one_or_none()
    if not test_row:
        now = iso_utc_now()
        test_row = OnlineTest(
            testId="TSTROW-" + os.urandom(16).hex(),
            token=token,
            candidateId=str(cand.candidateId or ""),
            requirementId=str(cand.requirementId or ""),
            issuedAt=now,
            expiresAt=expires_at,
            status="ISSUED",
            fullName="",
            applyingFor="",
            source="",
            questionsJson="",
            answersJson="",
            score=None,
            result="",
            submittedAt="",
            updatedAt=now,
        )
        db.add(test_row)

    if str(getattr(test_row, "status", "") or "").upper() == "SUBMITTED":
        raise ApiError("BAD_REQUEST", "ALREADY_SUBMITTED")

    full_name = str((data or {}).get("fullName") or "").strip()
    applying_for = str((data or {}).get("applyingFor") or "").strip()
    source = str((data or {}).get("source") or "").strip()
    answers = (data or {}).get("answers") or {}

    questions_json = str(getattr(test_row, "questionsJson", "") or "").strip()
    if not questions_json:
        raise ApiError("BAD_REQUEST", "QUESTIONS_NOT_READY")
    try:
        questions = json.loads(questions_json)
    except Exception:
        questions = None
    if not isinstance(questions, list) or len(questions) == 0:
        raise ApiError("BAD_REQUEST", "QUESTIONS_NOT_READY")

    score = 0
    total = 0
    for q in questions:
        if not isinstance(q, dict):
            continue
        w = int(_normalize_number(q.get("weight")) or 1)
        total += w

        user_raw = answers.get(q.get("id")) if isinstance(answers, dict) else None
        user_n = _normalize_number(user_raw)
        corr_n = _normalize_number(q.get("correct"))
        ok2 = False
        if user_n is not None and corr_n is not None:
            ok2 = abs(user_n - corr_n) <= 0.0001
        if ok2:
            score += w

    pass_marks = _get_setting_number(db, "ONLINE_TEST_PASS_MARK", 6)
    result = "PASS" if score >= pass_marks else "FAIL"
    now = iso_utc_now()

    test_row.status = "SUBMITTED"
    test_row.fullName = full_name
    test_row.applyingFor = applying_for
    test_row.source = source
    test_row.answersJson = json.dumps(answers or {})
    test_row.score = int(score)
    test_row.result = result
    test_row.submittedAt = now
    test_row.updatedAt = now

    append_audit(
        db,
        entityType="ONLINE_TEST",
        entityId=str(cand.candidateId or ""),
        action="TEST_SUBMIT_PUBLIC",
        fromState="",
        toState=result,
        stageTag="Online Test Submit",
        remark=f"Score {score}/{total}",
        actor=None,
        at=now,
        meta={"tokenPrefix": token[:8], "requirementId": str(cand.requirementId or "")},
    )

    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")
    update_candidate(
        db,
        cand=cand,
        patch={"onlineTestScore": int(score), "onlineTestResult": result, "onlineTestSubmittedAt": now},
        auth=system,
    )

    return {"ok": True, "submittedAt": now}


def test_result_get(data, auth: AuthContext | None, db, cfg):
    token = str((data or {}).get("token") or "").strip()
    if not token:
        raise ApiError("BAD_REQUEST", "MISSING_TOKEN")

    test_row = db.execute(select(OnlineTest).where(OnlineTest.token == token)).scalar_one_or_none()
    if not test_row:
        raise ApiError("BAD_REQUEST", "NOT_FOUND")

    if str(getattr(test_row, "status", "") or "").upper() != "SUBMITTED":
        raise ApiError("BAD_REQUEST", "NOT_SUBMITTED")

    return {"ok": True, "submittedAt": getattr(test_row, "submittedAt", "") or ""}


# __PIPELINE_GEN_MARKER__


def joining_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).where(func.upper(Candidate.status).in_(["SELECTED", "JOINING"]))).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        total += 1
        if count_only:
            continue
        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "jobRole": c.jobRole,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "status": c.status or "",
                "cvFileId": c.cvFileId,
                "cvFileName": c.cvFileName,
                "joiningAt": c.joiningAt or "",
                "docs": _parse_json_list(c.docsJson or ""),
                "docsCompleteAt": c.docsCompleteAt or "",
                "joinedAt": c.joinedAt or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def joining_set_date(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    joining_at_iso = str((data or {}).get("joiningAt") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not joining_at_iso:
        raise ApiError("BAD_REQUEST", "Missing joiningAt")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    dt = parse_datetime_maybe(joining_at_iso, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid joiningAt")
    joining_at = to_iso_utc(dt)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"SELECTED", "JOINING"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Joining workflow")

    update_candidate(db, cand=cand, patch={"status": "JOINING", "joiningAt": joining_at}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="JOINING_SET_DATE",
        fromState=current_status,
        toState="JOINING",
        stageTag="JOINING_SET_DATE",
        remark="",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "joiningAt": joining_at},
    )

    return {"ok": True, "status": "JOINING", "joiningAt": joining_at}


def docs_upload(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    docs = (data or {}).get("docs") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not isinstance(docs, list) or len(docs) == 0:
        raise ApiError("BAD_REQUEST", "Missing docs")
    if len(docs) > 10:
        raise ApiError("BAD_REQUEST", "Max 10 docs")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"SELECTED", "JOINING"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Joining workflow")

    existing = _parse_json_list(cand.docsJson or "")
    uploaded: list[dict[str, Any]] = []

    os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    for i, d in enumerate(docs):
        d = d or {}
        filename = str(d.get("filename") or "").strip() or "doc"
        mime_type = str(d.get("mimeType") or "").strip() or "application/octet-stream"
        base64 = str(d.get("base64") or "").strip()
        doc_type = str(d.get("docType") or "").strip()

        if not base64:
            raise ApiError("BAD_REQUEST", f"Missing base64 for doc index {i}")

        bytes_ = decode_base64_to_bytes(base64)
        safe_name = sanitize_filename(filename)
        file_id = os.urandom(16).hex()
        type_part = sanitize_filename(doc_type) + "_" if doc_type else ""
        out_name = f"DOC_{requirement_id}_{candidate_id}_{type_part}{stamp}_{safe_name}"
        out_path = os.path.join(cfg.UPLOAD_DIR, f"{file_id}_{out_name}")
        with open(out_path, "wb") as f:
            f.write(bytes_)

        uploaded.append(
            {
                "docType": doc_type or "",
                "fileId": file_id,
                "fileName": safe_name,
                "mimeType": mime_type,
                "uploadedAt": iso_utc_now(),
            }
        )

    next_docs = existing + uploaded
    update_candidate(db, cand=cand, patch={"docsJson": json.dumps(next_docs), "docsCompleteAt": ""}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="DOCS_UPLOAD",
        fromState=current_status,
        toState=current_status,
        stageTag="DOCS_UPLOAD",
        remark=f"Uploaded {len(uploaded)} doc(s)",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "count": len(uploaded)},
    )

    return {"ok": True, "uploaded": uploaded, "totalDocs": len(next_docs)}


def docs_complete(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"SELECTED", "JOINING"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Joining workflow")

    if not str(cand.docsJson or "").strip():
        raise ApiError("BAD_REQUEST", "No docs uploaded")

    now = iso_utc_now()
    update_candidate(db, cand=cand, patch={"docsCompleteAt": now}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="DOCS_COMPLETE",
        fromState=current_status,
        toState=current_status,
        stageTag="DOCS_COMPLETE",
        remark="",
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )

    return {"ok": True, "status": current_status, "docsCompleteAt": now}


def _increment_requirement_joined_count(db, requirement_id: str, auth: AuthContext) -> dict[str, Any]:
    req = (
        db.execute(select(Requirement).where(Requirement.requirementId == requirement_id).with_for_update(of=Requirement))
        .scalars()
        .first()
    )
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    if required_count <= 0:
        raise ApiError("BAD_REQUEST", "Invalid requiredCount")
    if joined_count < 0:
        joined_count = 0
    if joined_count >= required_count:
        raise ApiError("BAD_REQUEST", "Requirement already filled")

    now = iso_utc_now()
    next_joined = joined_count + 1
    req.joinedCount = next_joined
    req.updatedAt = now
    req.updatedBy = auth.email

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus="",
        toStatus="",
        stageTag="JOINED_COUNT_INC",
        remark="",
        actor=auth,
        meta={"joinedCount": next_joined, "requiredCount": required_count},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="JOINED_COUNT_INC",
        fromState="",
        toState="",
        stageTag="JOINED_COUNT_INC",
        remark="",
        actor=auth,
        at=now,
        meta={"joinedCount": next_joined, "requiredCount": required_count},
    )

    status = str(req.status or "").upper()
    auto_closed = False
    if next_joined == required_count and status != "CLOSED":
        req.status = "CLOSED"
        req.latestRemark = "Auto closed (JoinedCount reached RequiredCount)"
        req.updatedAt = now
        req.updatedBy = auth.email

        append_requirement_history(
            db,
            requirementId=requirement_id,
            fromStatus=status,
            toStatus="CLOSED",
            stageTag="REQUIREMENT_AUTO_CLOSE",
            remark="Auto closed",
            actor=auth,
            meta={"joinedCount": next_joined, "requiredCount": required_count},
        )
        append_audit(
            db,
            entityType="REQUIREMENT",
            entityId=requirement_id,
            action="REQUIREMENT_AUTO_CLOSE",
            fromState=status,
            toState="CLOSED",
            stageTag="REQUIREMENT_AUTO_CLOSE",
            remark="Auto closed",
            actor=auth,
            at=now,
            meta={"joinedCount": next_joined, "requiredCount": required_count},
        )
        status = "CLOSED"
        auto_closed = True

    return {
        "ok": True,
        "requirementId": requirement_id,
        "joinedCount": next_joined,
        "requiredCount": required_count,
        "status": status,
        "autoClosed": auto_closed,
    }


def mark_join(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "JOINING":
        raise ApiError("BAD_REQUEST", "Candidate not in JOINING")
    if not str(cand.joiningAt or "").strip():
        raise ApiError("BAD_REQUEST", "Set joining date first")
    if not str(cand.docsCompleteAt or "").strip():
        raise ApiError("BAD_REQUEST", "Docs not complete")

    now = iso_utc_now()
    update_candidate(db, cand=cand, patch={"status": "JOINED", "joinedAt": now}, auth=auth)

    append_join_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        action="MARK_JOIN",
        stageTag="MARK_JOIN",
        remark=remark or "",
        actor=auth,
    )
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="MARK_JOIN",
        fromState=current_status,
        toState="JOINED",
        stageTag="MARK_JOIN",
        remark=remark or "",
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )

    inc = _increment_requirement_joined_count(db, requirement_id, auth)
    return {
        "ok": True,
        "status": "JOINED",
        "joinedAt": now,
        "requirement": {
            "requirementId": requirement_id,
            "joinedCount": inc.get("joinedCount"),
            "requiredCount": inc.get("requiredCount"),
            "status": inc.get("status"),
            "autoClosed": inc.get("autoClosed"),
        },
    }


def requirement_auto_close(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    req = (
        db.execute(select(Requirement).where(Requirement.requirementId == requirement_id).with_for_update(of=Requirement))
        .scalars()
        .first()
    )
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")

    required_count = int(req.requiredCount or 0)
    joined_count = int(req.joinedCount or 0)
    current_status = str(req.status or "").upper()
    if required_count <= 0:
        raise ApiError("BAD_REQUEST", "Invalid requiredCount")
    if joined_count < 0:
        joined_count = 0

    if current_status == "CLOSED":
        return {"ok": True, "requirementId": requirement_id, "closed": True, "status": "CLOSED", "joinedCount": joined_count, "requiredCount": required_count}
    if joined_count != required_count:
        return {"ok": True, "requirementId": requirement_id, "closed": False, "status": current_status, "joinedCount": joined_count, "requiredCount": required_count}

    now = iso_utc_now()
    req.status = "CLOSED"
    req.latestRemark = "Auto closed (JoinedCount reached RequiredCount)"
    req.updatedAt = now
    req.updatedBy = auth.email

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus=current_status,
        toStatus="CLOSED",
        stageTag="REQUIREMENT_AUTO_CLOSE",
        remark="Auto closed",
        actor=auth,
        meta={"joinedCount": joined_count, "requiredCount": required_count},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="REQUIREMENT_AUTO_CLOSE",
        fromState=current_status,
        toState="CLOSED",
        stageTag="REQUIREMENT_AUTO_CLOSE",
        remark="Auto closed",
        actor=auth,
        at=now,
        meta={"joinedCount": joined_count, "requiredCount": required_count},
    )

    return {"ok": True, "requirementId": requirement_id, "closed": True, "status": "CLOSED", "joinedCount": joined_count, "requiredCount": required_count}



def final_interview_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))

    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate)).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0
    for c in rows:
        status = str(c.status or "").upper()
        if status == "REJECTED":
            continue
        if status in {"SELECTED", "JOINING", "JOINED", "PROBATION", "EMPLOYEE", "FINAL_HOLD"}:
            continue

        tech_res = str(c.techResult or "").upper()
        if tech_res != "PASS" and not (tech_res == "FAIL" and is_test_continued(c, "TECHNICAL")):
            continue

        total += 1
        if count_only:
            continue

        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        job_role = str(c.jobRole or rm.get("jobRole", "") or "").strip()

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "status": c.status or "",
                "inPersonMarks": c.inPersonMarks or "",
                "techSelectedTests": c.techSelectedTestsJson or "",
                "tallyMarks": c.tallyMarks or "",
                "voiceMarks": c.voiceMarks or "",
                "techReview": c.techReview or "",
                "excelMarks": c.excelMarks or "",
                "excelReview": c.excelReview or "",
                "techEvaluatedAt": c.techEvaluatedAt or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
            }
        )

    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def final_send_owner(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate is rejected")
    if current_status == "FINAL_OWNER_PENDING":
        return {"ok": True, "status": "FINAL_OWNER_PENDING"}

    tech = str(cand.techResult or "").upper()
    if tech != "PASS" and not (tech == "FAIL" and is_test_continued(cand, "TECHNICAL")):
        raise ApiError("BAD_REQUEST", "Candidate not allowed for final (technical not cleared)")

    update_candidate(db, cand=cand, patch={"status": "FINAL_OWNER_PENDING"}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="FINAL_SEND_OWNER",
        fromState=current_status,
        toState="FINAL_OWNER_PENDING",
        stageTag="FINAL_SEND_OWNER",
        remark="",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id},
    )

    return {"ok": True, "status": "FINAL_OWNER_PENDING"}


def hr_final_hold_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).where(func.upper(Candidate.status) == "FINAL_HOLD")).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        total += 1
        if count_only:
            continue

        requirement_id = str(c.requirementId or "")
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "jobRole": c.jobRole,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "status": c.status or "",
                "cvFileId": c.cvFileId,
                "cvFileName": c.cvFileName,
                "finalHoldAt": c.finalHoldAt or "",
                "finalHoldRemark": c.finalHoldRemark or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def hr_hold_schedule(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    final_hold_at_iso = str((data or {}).get("finalHoldAt") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not final_hold_at_iso:
        raise ApiError("BAD_REQUEST", "Missing finalHoldAt")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    dt = parse_datetime_maybe(final_hold_at_iso, app_timezone=cfg.APP_TIMEZONE)
    if not dt:
        raise ApiError("BAD_REQUEST", "Invalid finalHoldAt")
    final_hold_at = to_iso_utc(dt)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "FINAL_HOLD":
        raise ApiError("BAD_REQUEST", "Candidate not in Final Hold")

    update_candidate(
        db,
        cand=cand,
        patch={"finalHoldAt": final_hold_at, "finalHoldRemark": remark or (cand.finalHoldRemark or "")},
        auth=auth,
    )
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="HR_HOLD_SCHEDULE",
        fromState=current_status,
        toState=current_status,
        stageTag="Final Hold",
        remark=remark or "",
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "finalHoldAt": final_hold_at},
    )

    return {"ok": True, "status": current_status, "finalHoldAt": final_hold_at}


def auto_reject_final_noshow(data, auth: AuthContext | None, db, cfg):
    rows = db.execute(select(Candidate)).scalars().all()
    scanned = len(rows)
    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    rejected = 0

    for c in rows:
        if str(c.status or "").upper() != "FINAL_HOLD":
            continue
        hold_at_raw = str(c.finalHoldAt or "").strip()
        if not hold_at_raw:
            continue
        hold_at = parse_datetime_maybe(hold_at_raw, app_timezone=cfg.APP_TIMEZONE)
        if not hold_at:
            continue
        if hold_at > now_dt:
            continue
        try:
            res = reject_candidate_with_meta(
                db,
                candidate_id=str(c.candidateId or ""),
                requirement_id=str(c.requirementId or ""),
                stage_tag="Final Hold No-show",
                remark="Auto rejected (Final Hold No-show)",
                reason_code="FINAL_NOSHOW",
                auth=None,
            )
            if res and res.get("ok"):
                rejected += 1
        except Exception:
            pass

    return {"scanned": scanned, "rejected": rejected, "at": now_iso}


# __PIPELINE_GEN_MARKER__

def tech_pending_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))

    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).order_by(Candidate.candidateId.asc())).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        status = str(c.status or "").upper()
        if status == "REJECTED":
            continue

        online_res = str(c.onlineTestResult or "").upper()
        if online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(c, "ONLINE_TEST")):
            continue

        in_marks = c.inPersonMarks
        if in_marks is None:
            continue
        if int(in_marks) < 6 and not is_test_continued(c, "INPERSON_MARKS"):
            continue

        selected_json = str(c.techSelectedTestsJson or "").strip()
        if not selected_json:
            continue

        tech_result = str(c.techResult or "").upper()
        if tech_result == "PASS":
            continue
        if tech_result == "FAIL" and is_test_continued(c, "TECHNICAL"):
            continue

        total += 1
        if count_only:
            continue

        selected = _parse_json_list(selected_json)
        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        job_role = str(c.jobRole or rm.get("jobRole", "") or "").strip()

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "inPersonMarks": c.inPersonMarks or "",
                "selectedTests": selected,
                "tallyMarks": c.tallyMarks or "",
                "voiceMarks": c.voiceMarks or "",
                "techReview": c.techReview or "",
                "excelMarks": c.excelMarks or "",
                "excelReview": c.excelReview or "",
                "techResult": c.techResult or "",
                "techEvaluatedAt": c.techEvaluatedAt or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def ea_tech_marks_submit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    review = str((data or {}).get("review") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")

    tally_raw = (data or {}).get("tallyMarks") if isinstance(data, dict) else None
    voice_raw = (data or {}).get("voiceMarks") if isinstance(data, dict) else None

    tally = None
    voice = None
    if tally_raw is not None:
        try:
            tally = float(tally_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid tallyMarks")
        if tally < 0 or tally > 10:
            raise ApiError("BAD_REQUEST", "Invalid tallyMarks")
    if voice_raw is not None:
        try:
            voice = float(voice_raw)
        except Exception:
            raise ApiError("BAD_REQUEST", "Invalid voiceMarks")
        if voice < 0 or voice > 10:
            raise ApiError("BAD_REQUEST", "Invalid voiceMarks")

    if not review:
        raise ApiError("BAD_REQUEST", "Test Review required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    patch: dict[str, Any] = {"techReview": review}
    if tally is not None:
        patch["tallyMarks"] = int(tally)
    if voice is not None:
        patch["voiceMarks"] = int(voice)

    update_candidate(db, cand=cand, patch=patch, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="EA_TECH_MARKS_SUBMIT",
        fromState=status,
        toState=status,
        stageTag="EA Tech Marks Submit",
        remark=review,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "tallyMarks": tally, "voiceMarks": voice, "review": review},
    )

    return passfail_evaluate({"requirementId": requirement_id, "candidateId": candidate_id}, auth, db, cfg)


def admin_excel_marks_submit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    review = str((data or {}).get("review") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")

    excel_raw = (data or {}).get("excelMarks") if isinstance(data, dict) else None
    if excel_raw is None:
        raise ApiError("BAD_REQUEST", "Invalid excelMarks")
    try:
        excel = float(excel_raw)
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid excelMarks")
    if excel < 0 or excel > 10:
        raise ApiError("BAD_REQUEST", "Invalid excelMarks")
    if not review:
        raise ApiError("BAD_REQUEST", "Test Review required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    update_candidate(db, cand=cand, patch={"excelMarks": int(excel), "excelReview": review}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ADMIN_EXCEL_MARKS_SUBMIT",
        fromState=status,
        toState=status,
        stageTag="Admin Excel Marks Submit",
        remark=review,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "excelMarks": excel, "review": review},
    )

    return passfail_evaluate({"requirementId": requirement_id, "candidateId": candidate_id}, auth, db, cfg)


def _evaluate_technical(db, cand: Candidate) -> dict[str, Any]:
    selected = _parse_json_list(cand.techSelectedTestsJson or "")
    if not selected:
        return {"state": "NO_SELECTION", "selected": []}

    thresholds = {
        "Tally": _get_setting_number(db, "TALLY_PASS_MARK", 6),
        "Voice": _get_setting_number(db, "VOICE_PASS_MARK", 6),
        "Excel": _get_setting_number(db, "EXCEL_PASS_MARK", 6),
    }
    marks_map = {"Tally": cand.tallyMarks, "Voice": cand.voiceMarks, "Excel": cand.excelMarks}

    missing: list[str] = []
    failed: list[dict[str, Any]] = []
    for t in selected:
        tt = str(t or "").strip()
        if not tt:
            continue
        th = float(thresholds.get(tt, 6))
        m = marks_map.get(tt)
        if m is None or str(m).strip() == "":
            missing.append(tt)
            continue
        try:
            mn = float(m)
        except Exception:
            missing.append(tt)
            continue
        if mn < th:
            failed.append({"test": tt, "marks": mn, "threshold": th})

    if missing:
        return {"state": "PENDING", "selected": selected, "missing": missing, "thresholds": thresholds}
    if failed:
        return {"state": "FAIL", "selected": selected, "failed": failed, "thresholds": thresholds}
    return {"state": "PASS", "selected": selected, "thresholds": thresholds}


def passfail_evaluate(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        return {"ok": True, "status": "REJECTED", "techResult": "FAIL"}

    eval_res = _evaluate_technical(db, cand)
    now = iso_utc_now()

    if eval_res.get("state") == "PENDING":
        return {"ok": True, "status": status, "state": "PENDING", "missing": eval_res.get("missing"), "selected": eval_res.get("selected")}

    if eval_res.get("state") == "FAIL":
        update_candidate(db, cand=cand, patch={"techResult": "FAIL", "techEvaluatedAt": now}, auth=auth)
        failed = eval_res.get("failed") or []
        stage_tag = "Technical Tests"
        if isinstance(failed, list) and len(failed) == 1 and isinstance(failed[0], dict):
            stage_tag = f"{str(failed[0].get('test') or '')} Test".strip() or "Technical Tests"
        return {
            "ok": True,
            "status": status,
            "techResult": "FAIL",
            "failed": failed,
            "passFail": "FAIL",
            "decisionRequired": True,
            "testType": "TECHNICAL",
            "stageTag": stage_tag,
        }

    if eval_res.get("state") == "PASS":
        update_candidate(db, cand=cand, patch={"techResult": "PASS", "techEvaluatedAt": now}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PASSFAIL_EVALUATE",
            fromState=status,
            toState=status,
            stageTag="Technical Pass",
            remark="",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "selected": eval_res.get("selected") or []},
        )
        return {"ok": True, "status": status, "techResult": "PASS", "selected": eval_res.get("selected") or [], "techEvaluatedAt": now}

    return {"ok": True, "status": status, "state": eval_res.get("state")}


def test_fail_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    test_type = str((data or {}).get("testType") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    stage_tag = str((data or {}).get("stageTag") or "").strip()
    meta = (data or {}).get("meta") or {}

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not test_type:
        raise ApiError("BAD_REQUEST", "Missing testType")
    if decision not in {"CONTINUE", "REJECT"}:
        raise ApiError("BAD_REQUEST", "Invalid decision")
    if decision == "REJECT" and not remark:
        raise ApiError("BAD_REQUEST", "Remark required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    if not stage_tag:
        if test_type == "ONLINE_TEST":
            stage_tag = "Online Test"
        elif test_type == "INPERSON_MARKS":
            stage_tag = "In-person Marks"
        elif test_type == "TECHNICAL":
            try:
                failed = meta.get("failed") if isinstance(meta, dict) else None
                if isinstance(failed, list) and len(failed) == 1 and isinstance(failed[0], dict):
                    stage_tag = f"{str(failed[0].get('test') or '')} Test".strip()
            except Exception:
                pass
            if not stage_tag:
                stage_tag = "Technical Tests"
        else:
            stage_tag = test_type

    decision_meta = {
        "stageTag": stage_tag,
        "marks": meta.get("marks") if isinstance(meta, dict) else "",
        "passFail": "FAIL",
        "failed": meta.get("failed") if isinstance(meta, dict) else None,
    }

    if decision == "CONTINUE":
        return upsert_test_decision(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            test_type=test_type,
            decision=decision,
            remark=remark,
            meta=decision_meta,
            auth=auth,
        )

    upsert_test_decision(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        test_type=test_type,
        decision=decision,
        remark=remark,
        meta=decision_meta,
        auth=auth,
    )

    reason_code = "TEST_FAIL_MANUAL"
    if test_type == "ONLINE_TEST":
        reason_code = "ONLINE_TEST_FAIL_MANUAL"
    elif test_type == "TECHNICAL":
        reason_code = "TECH_FAIL_MANUAL"
    elif test_type == "INPERSON_MARKS":
        reason_code = "INPERSON_FAIL_MANUAL"

    rej = reject_candidate_with_meta(
        db,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        stage_tag=stage_tag,
        remark=remark,
        reason_code=reason_code,
        auth=auth,
    )
    return {"ok": True, "decision": "REJECT", "status": "REJECTED", "rejectedReasonCode": reason_code, "rejection": rej}


# __PIPELINE_GEN_MARKER__

def inperson_pipeline_list(data, auth: AuthContext | None, db, cfg):
    job_role_filter = str((data or {}).get("jobRole") or "").strip()
    count_only = bool((data or {}).get("countOnly"))

    req_map = None
    if not count_only or job_role_filter:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate)).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        status = str(c.status or "").upper()
        if status == "REJECTED":
            continue

        online_res = str(c.onlineTestResult or "").upper()
        if online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(c, "ONLINE_TEST")):
            continue

        tech_res = str(c.techResult or "").upper()
        if tech_res in {"PASS", "FAIL"}:
            continue

        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}
        job_role = str(c.jobRole or rm.get("jobRole", "") or "").strip()
        if job_role_filter and job_role != job_role_filter:
            continue

        total += 1
        if count_only:
            continue

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "source": c.source,
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "onlineTestScore": c.onlineTestScore or "",
                "onlineTestResult": c.onlineTestResult or "",
                "onlineTestSubmittedAt": c.onlineTestSubmittedAt or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": bool(c.candidate_test_failed_but_manually_continued) or False,
                "inPersonMarks": c.inPersonMarks or "",
                "inPersonMarksAt": c.inPersonMarksAt or "",
                "techSelectedTests": _parse_json_list(c.techSelectedTestsJson or ""),
                "techSelectedAt": c.techSelectedAt or "",
                "allowedTechTests": _allowed_tech_tests_for_role(job_role),
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("onlineTestSubmittedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def inperson_marks_save(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    marks_raw = (data or {}).get("marks") if isinstance(data, dict) else ""

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    try:
        marks = float(marks_raw)
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid marks")
    if marks < 0 or marks > 10:
        raise ApiError("BAD_REQUEST", "Marks must be 0-10")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    online_res = str(cand.onlineTestResult or "").upper()
    if online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(cand, "ONLINE_TEST")):
        raise ApiError("BAD_REQUEST", "Online test not allowed")

    now = iso_utc_now()
    update_candidate(db, cand=cand, patch={"inPersonMarks": int(marks), "inPersonMarksAt": now}, auth=auth)

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="INPERSON_MARKS_SAVE",
        fromState=current_status,
        toState=current_status,
        stageTag="In-person Marks Save",
        remark=str(int(marks)),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )

    if marks < 6:
        return {
            "ok": True,
            "status": current_status,
            "inPersonMarks": int(marks),
            "passFail": "FAIL",
            "decisionRequired": True,
            "testType": "INPERSON_MARKS",
            "stageTag": "In-person Marks",
            "marksScale": "0-10",
        }

    return {"ok": True, "status": current_status, "inPersonMarks": int(marks), "passFail": "PASS", "decisionRequired": False}


def tech_select(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    tests = (data or {}).get("tests") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not isinstance(tests, list):
        raise ApiError("BAD_REQUEST", "Invalid tests")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status == "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate rejected")

    online_res = str(cand.onlineTestResult or "").upper()
    if online_res != "PASS" and not (online_res == "FAIL" and is_test_continued(cand, "ONLINE_TEST")):
        raise ApiError("BAD_REQUEST", "Online test not allowed")

    marks = cand.inPersonMarks
    if marks is None:
        raise ApiError("BAD_REQUEST", "In-person marks missing")
    if int(marks) < 6 and not is_test_continued(cand, "INPERSON_MARKS"):
        raise ApiError("BAD_REQUEST", "In-person marks must be >=6 (or HR override)")

    allowed = _allowed_tech_tests_for_role(cand.jobRole)
    uniq: set[str] = set()
    selected: list[str] = []
    for t in tests:
        x = str(t or "").strip()
        if not x:
            continue
        if x not in allowed:
            raise ApiError("BAD_REQUEST", f"Invalid test: {x}")
        if x not in uniq:
            uniq.add(x)
            selected.append(x)

    if len(selected) == 0:
        raise ApiError("BAD_REQUEST", "Select at least one test")

    now = iso_utc_now()
    update_candidate(db, cand=cand, patch={"techSelectedTestsJson": json.dumps(selected), "techSelectedAt": now}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="TECH_SELECT",
        fromState=current_status,
        toState=current_status,
        stageTag="Tech Select",
        remark=", ".join(selected),
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "tests": selected},
    )
    return {"ok": True, "tests": selected, "techSelectedAt": now}


def auto_reject_inperson_low(data, auth: AuthContext | None, db, cfg):
    scanned = db.execute(select(func.count()).select_from(Candidate)).scalar_one() or 0
    return {"scanned": int(scanned), "rejected": 0, "disabled": True}


def probation_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))
    req_map = None
    if not count_only:
        req_map = _get_requirements_map(db)

    rows = db.execute(select(Candidate).where(func.upper(Candidate.status).in_(["JOINED", "PROBATION"]))).scalars().all()
    items: list[dict[str, Any]] = []
    total = 0

    for c in rows:
        total += 1
        if count_only:
            continue

        requirement_id = str(c.requirementId or "").strip()
        rm = (req_map or {}).get(requirement_id, {}) if requirement_id else {}

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": requirement_id,
                "candidateName": c.candidateName,
                "mobile": c.mobile,
                "source": c.source,
                "jobRole": c.jobRole or "",
                "jobTitle": rm.get("jobTitle", "") if isinstance(rm, dict) else "",
                "status": c.status or "",
                "cvFileId": c.cvFileId,
                "cvFileName": c.cvFileName,
                "joiningAt": c.joiningAt or "",
                "joinedAt": c.joinedAt or "",
                "probationStartAt": c.probationStartAt or "",
                "probationEndsAt": c.probationEndsAt or "",
                "employeeId": c.employeeId or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    items.sort(
        key=lambda x: parse_datetime_maybe(x.get("updatedAt") or "", app_timezone=cfg.APP_TIMEZONE)
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    if count_only:
        return {"items": [], "total": total}
    return {"items": items, "total": len(items)}


def _build_candidate_timeline(db, candidate_id: str, requirement_id: str) -> list[dict[str, Any]]:
    from models import AuditLog, HoldLog, JoinLog, RejectionLog

    entries: list[dict[str, Any]] = []

    for a in (
        db.execute(select(AuditLog).where(func.upper(AuditLog.entityType) == "CANDIDATE").where(AuditLog.entityId == candidate_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": a.at or "",
                "source": "AUDIT",
                "stageTag": a.stageTag or "",
                "action": a.action or "",
                "fromState": a.fromState or "",
                "toState": a.toState or "",
                "remark": a.remark or "",
                "actorRole": a.actorRole or "",
                "actorUserId": a.actorUserId or "",
                "metaJson": a.metaJson or "",
            }
        )

    for j in (
        db.execute(select(JoinLog).where(JoinLog.candidateId == candidate_id).where(JoinLog.requirementId == requirement_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": j.at or "",
                "source": "JOIN",
                "stageTag": j.stageTag or "",
                "action": j.action or "",
                "remark": j.remark or "",
                "actorRole": j.actorRole or "",
                "actorUserId": j.actorUserId or "",
            }
        )

    for h in (
        db.execute(select(HoldLog).where(HoldLog.candidateId == candidate_id).where(HoldLog.requirementId == requirement_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": h.at or "",
                "source": "HOLD",
                "stageTag": h.stageTag or "",
                "action": h.action or "",
                "remark": h.remark or "",
                "actorRole": h.actorRole or "",
                "actorUserId": h.actorUserId or "",
                "holdUntil": h.holdUntil or "",
            }
        )

    for r in (
        db.execute(select(RejectionLog).where(RejectionLog.candidateId == candidate_id).where(RejectionLog.requirementId == requirement_id))
        .scalars()
        .all()
    ):
        entries.append(
            {
                "at": r.at or "",
                "source": "REJECT",
                "stageTag": r.stageTag or "",
                "action": "REJECT",
                "remark": r.remark or "",
                "actorRole": r.actorRole or "",
                "actorUserId": r.actorUserId or "",
                "rejectionType": r.rejectionType or "",
                "autoRejectCode": r.autoRejectCode or "",
            }
        )

    def _ts(x: dict[str, Any]) -> datetime:
        return parse_datetime_maybe(x.get("at") or "", app_timezone="UTC") or datetime.min.replace(tzinfo=timezone.utc)

    entries.sort(key=_ts)
    return entries


def _create_employee_from_candidate(db, candidate_id: str, requirement_id: str, auth: AuthContext) -> dict[str, Any]:
    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    existing = str(cand.employeeId or "").strip()
    if existing:
        return {"ok": True, "employeeId": existing, "alreadyExists": True}

    joined_at = str(cand.joinedAt or "").strip()
    if not joined_at:
        raise ApiError("BAD_REQUEST", "Candidate not marked joined")

    timeline = _build_candidate_timeline(db, candidate_id, requirement_id)
    req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
    job_title = (req and (req.jobTitle or "")) or ""

    employee_id = "EMP-" + os.urandom(16).hex()[:8].upper()
    now = iso_utc_now()

    db.add(
        Employee(
            employeeId=employee_id,
            candidateId=candidate_id,
            requirementId=requirement_id,
            employeeName=cand.candidateName or "",
            mobile=cand.mobile or "",
            jobRole=cand.jobRole or "",
            jobTitle=job_title,
            source=cand.source or "",
            cvFileId=cand.cvFileId or "",
            cvFileName=cand.cvFileName or "",
            joinedAt=joined_at,
            probationStartAt=cand.probationStartAt or "",
            probationEndsAt=cand.probationEndsAt or "",
            createdAt=now,
            createdBy=auth.email,
            timelineJson=json.dumps(timeline),
        )
    )

    update_candidate(db, cand=cand, patch={"employeeId": employee_id}, auth=auth)

    append_audit(
        db,
        entityType="EMPLOYEE",
        entityId=employee_id,
        action="EMPLOYEE_CREATE_FROM_CANDIDATE",
        fromState="",
        toState="",
        stageTag="EMPLOYEE_CREATE_FROM_CANDIDATE",
        remark="",
        actor=auth,
        at=now,
        meta={"candidateId": candidate_id, "requirementId": requirement_id},
    )

    return {"ok": True, "employeeId": employee_id, "alreadyExists": False, "timeline": timeline}


def probation_set(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    try:
        days = float((data or {}).get("probationDays") or 0)
    except Exception:
        days = 0

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not (days and days > 0 and days <= 365):
        raise ApiError("BAD_REQUEST", "Invalid probationDays")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"JOINED", "PROBATION"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Probation flow")
    if str(cand.employeeId or "").strip():
        raise ApiError("BAD_REQUEST", "Employee already created")
    if not str(cand.joinedAt or "").strip():
        raise ApiError("BAD_REQUEST", "Candidate not marked joined")

    now_dt = datetime.now(timezone.utc)
    now = iso_utc_now()
    ends = to_iso_utc(now_dt + timedelta(days=int(days)))

    update_candidate(db, cand=cand, patch={"status": "PROBATION", "probationStartAt": now, "probationEndsAt": ends}, auth=auth)
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="PROBATION_SET",
        fromState=current_status,
        toState="PROBATION",
        stageTag="PROBATION_SET",
        remark=f"{int(days)} day(s)",
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id, "probationDays": int(days), "probationEndsAt": ends},
    )

    emp = _create_employee_from_candidate(db, candidate_id, requirement_id, auth)
    return {
        "ok": True,
        "status": "PROBATION",
        "probationStartAt": now,
        "probationEndsAt": ends,
        "probationDays": int(days),
        "employeeId": emp.get("employeeId"),
    }


def probation_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not decision:
        raise ApiError("BAD_REQUEST", "Missing decision")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status != "PROBATION":
        raise ApiError("BAD_REQUEST", "Candidate not in PROBATION")
    if str(cand.employeeId or "").strip():
        raise ApiError("BAD_REQUEST", "Employee already created")

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        rej = reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Probation Reject",
            remark=remark,
            reason_code="PROBATION_REJECT",
            auth=auth,
        )
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PROBATION_DECIDE",
            fromState=current_status,
            toState="REJECTED",
            stageTag="Probation Reject",
            remark=remark,
            actor=auth,
            at=iso_utc_now(),
            meta={"requirementId": requirement_id, "reasonCode": "PROBATION_REJECT"},
        )
        return rej

    if decision == "COMPLETE":
        if not str(cand.probationStartAt or "").strip() or not str(cand.probationEndsAt or "").strip():
            raise ApiError("BAD_REQUEST", "Probation not set")

        ts = training_summary({"candidateId": candidate_id}, auth, db, cfg)
        counts = (ts or {}).get("counts") if isinstance(ts, dict) else None
        if not counts or not counts.get("TOTAL"):
            raise ApiError("BAD_REQUEST", "Training not assigned")
        open_count = int(counts.get("PENDING") or 0) + int(counts.get("IN_PROGRESS") or 0) + int(counts.get("OVERDUE") or 0)
        if open_count > 0:
            raise ApiError("BAD_REQUEST", "Training not completed yet")

        created = _create_employee_from_candidate(db, candidate_id, requirement_id, auth)
        update_candidate(db, cand=cand, patch={"status": "EMPLOYEE"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="PROBATION_DECIDE",
            fromState=current_status,
            toState="EMPLOYEE",
            stageTag="PROBATION_COMPLETE",
            remark="",
            actor=auth,
            at=iso_utc_now(),
            meta={"requirementId": requirement_id, "employeeId": created.get("employeeId")},
        )
        return {"ok": True, "status": "EMPLOYEE", "employeeId": created.get("employeeId")}

    raise ApiError("BAD_REQUEST", "Invalid decision")


def role_change(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    next_role = str((data or {}).get("jobRole") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not next_role:
        raise ApiError("BAD_REQUEST", "Missing jobRole")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    current_status = str(cand.status or "").upper()
    if current_status not in {"JOINED", "PROBATION"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Probation flow")
    if str(cand.employeeId or "").strip():
        raise ApiError("BAD_REQUEST", "Employee already created")

    update_candidate(
        db,
        cand=cand,
        patch={"jobRole": next_role, "status": "JOINED", "probationStartAt": "", "probationEndsAt": ""},
        auth=auth,
    )
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="ROLE_CHANGE",
        fromState=current_status,
        toState="JOINED",
        stageTag="ROLE_CHANGE",
        remark=remark or next_role,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "jobRole": next_role},
    )
    return {"ok": True, "status": "JOINED", "jobRole": next_role}


def employee_create_from_candidate(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)
    return _create_employee_from_candidate(db, candidate_id, requirement_id, auth)


def employee_get(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")

    emp = db.execute(select(Employee).where(Employee.employeeId == employee_id)).scalar_one_or_none()
    if not emp:
        raise ApiError("NOT_FOUND", "Employee not found")

    timeline = _parse_json_list(emp.timelineJson or "")
    requirement_id = str(emp.requirementId or "").strip()
    job_title = emp.jobTitle or ""
    if not job_title and requirement_id:
        req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
        job_title = (req and (req.jobTitle or "")) or ""

    return {
        "employeeId": employee_id,
        "candidateId": emp.candidateId or "",
        "requirementId": requirement_id,
        "employeeName": emp.employeeName or "",
        "mobile": emp.mobile or "",
        "jobRole": emp.jobRole or "",
        "jobTitle": job_title,
        "source": emp.source or "",
        "cvFileId": emp.cvFileId or "",
        "cvFileName": emp.cvFileName or "",
        "joinedAt": emp.joinedAt or "",
        "probationStartAt": emp.probationStartAt or "",
        "probationEndsAt": emp.probationEndsAt or "",
        "createdAt": emp.createdAt or "",
        "createdBy": emp.createdBy or "",
        "timeline": timeline,
    }


def hold_expiry_cron(data, auth: AuthContext | None, db, cfg):
    values = db.execute(select(Candidate)).scalars().all()
    scanned = len(values)
    expired = 0
    now_dt = datetime.now(timezone.utc)
    system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="SYSTEM", expiresAt="")

    for c in values:
        if str(c.status or "").upper() != "OWNER_HOLD":
            continue
        hold_until = str(c.holdUntil or "").strip()
        if not hold_until:
            continue
        hold_dt = parse_datetime_maybe(hold_until, app_timezone=cfg.APP_TIMEZONE)
        if not hold_dt:
            continue
        if hold_dt <= now_dt:
            update_candidate(db, cand=c, patch={"status": "REJECTED", "holdUntil": ""}, auth=system)
            append_rejection_log(
                db,
                candidateId=str(c.candidateId or ""),
                requirementId=str(c.requirementId or ""),
                stageTag="Owner Hold Expired",
                remark="Hold expired",
                actor=None,
                reasonCode="HOLD_EXPIRED",
            )
            expired += 1

    return {"scanned": scanned, "expired": expired}
