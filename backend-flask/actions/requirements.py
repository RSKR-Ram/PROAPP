from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from actions.helpers import append_audit, append_requirement_history, next_prefixed_id, require_requirement
from models import Candidate, JobPosting, JobTemplate, Requirement
from utils import ApiError, AuthContext, iso_utc_now


def _get_template_by_id(db, template_id: str):
    tid = str(template_id or "").strip()
    if not tid:
        return None
    return db.execute(select(JobTemplate).where(JobTemplate.templateId == tid)).scalar_one_or_none()


def _next_requirement_id(db, cfg) -> str:
    try:
        tz = ZoneInfo(cfg.APP_TIMEZONE)
    except Exception:
        tz = timezone.utc
    now_local = datetime.now(tz)
    prefix = f"REQ-NTW-{now_local:%Y%m%d}-"
    existing = db.execute(select(Requirement.requirementId).where(Requirement.requirementId.like(f"{prefix}%"))).scalars().all()
    return next_prefixed_id(db, counter_key=prefix, prefix=prefix, pad=4, existing_ids=list(existing))


def requirement_create(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    template_id = str((data or {}).get("templateId") or "").strip()
    if not template_id:
        raise ApiError("BAD_REQUEST", "Missing templateId")

    t = _get_template_by_id(db, template_id)
    if not t:
        raise ApiError("BAD_REQUEST", "Template not found")
    if str(t.status or "").upper() != "ACTIVE":
        raise ApiError("BAD_REQUEST", "Template inactive")

    raised_for = str((data or {}).get("raisedFor") or "").strip()
    concerned_person = str((data or {}).get("concernedPerson") or "").strip()

    try:
        required_count = int((data or {}).get("requiredCount") or 0)
    except Exception:
        required_count = 0
    if required_count <= 0:
        raise ApiError("BAD_REQUEST", "Invalid requiredCount")

    job_role = str((data or {}).get("jobRole") or t.jobRole or "").strip()
    job_title = str((data or {}).get("jobTitle") or t.jobTitle or "").strip()
    jd = str((data or {}).get("jd") or t.jd or "").strip()
    responsibilities = str((data or {}).get("responsibilities") or t.responsibilities or "").strip()
    skills = str((data or {}).get("skills") or t.skills or "").strip()
    shift = str((data or {}).get("shift") or t.shift or "").strip()
    pay_scale = str((data or {}).get("payScale") or t.payScale or "").strip()
    perks = str((data or {}).get("perks") or t.perks or "").strip()
    notes = str((data or {}).get("notes") or t.notes or "").strip()

    if not job_role:
        raise ApiError("BAD_REQUEST", "Missing jobRole")
    if not job_title:
        raise ApiError("BAD_REQUEST", "Missing jobTitle")

    requirement_id = _next_requirement_id(db, cfg)
    now = iso_utc_now()

    db.add(
        Requirement(
            requirementId=requirement_id,
            templateId=template_id,
            jobRole=job_role,
            jobTitle=job_title,
            jd=jd,
            responsibilities=responsibilities,
            skills=skills,
            shift=shift,
            payScale=pay_scale,
            perks=perks,
            notes=notes,
            raisedFor=raised_for,
            concernedPerson=concerned_person,
            requiredCount=required_count,
            joinedCount=0,
            status="DRAFT",
            latestRemark="",
            createdAt=now,
            createdBy=auth.email,
            updatedAt=now,
            updatedBy=auth.email,
        )
    )

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus="",
        toStatus="DRAFT",
        stageTag="REQ_CREATED",
        remark="",
        actor=auth,
        meta={"templateId": template_id},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="REQUIREMENT_CREATE",
        fromState="",
        toState="DRAFT",
        stageTag="REQ_CREATED",
        remark="",
        actor=auth,
        at=now,
        meta={"templateId": template_id, "requiredCount": required_count},
    )

    return {"requirementId": requirement_id, "status": "DRAFT"}


def requirement_update(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")

    req = require_requirement(db, requirement_id)

    if str(auth.role or "") == "EA":
        created_by = str(req.createdBy or "").lower()
        if created_by != str(auth.email or "").lower():
            raise ApiError("FORBIDDEN", "Cannot edit others requirements")

    status = str(req.status or "").upper()
    if status not in {"DRAFT", "CLARIFICATION"}:
        raise ApiError("BAD_REQUEST", "Can only edit in DRAFT/CLARIFICATION")

    patch = {
        "raisedFor": (data or {}).get("raisedFor"),
        "concernedPerson": (data or {}).get("concernedPerson"),
        "requiredCount": (data or {}).get("requiredCount"),
        "jobRole": (data or {}).get("jobRole"),
        "jobTitle": (data or {}).get("jobTitle"),
        "jd": (data or {}).get("jd"),
        "responsibilities": (data or {}).get("responsibilities"),
        "skills": (data or {}).get("skills"),
        "shift": (data or {}).get("shift"),
        "payScale": (data or {}).get("payScale"),
        "perks": (data or {}).get("perks"),
        "notes": (data or {}).get("notes"),
        "latestRemark": None if str(auth.role or "") == "EA" else (data or {}).get("latestRemark"),
    }

    if patch["raisedFor"] is not None:
        req.raisedFor = str(patch["raisedFor"] or "").strip()
    if patch["concernedPerson"] is not None:
        req.concernedPerson = str(patch["concernedPerson"] or "").strip()

    if patch["requiredCount"] is not None:
        try:
            rc = int(patch["requiredCount"] or 0)
        except Exception:
            rc = 0
        if rc <= 0:
            raise ApiError("BAD_REQUEST", "Invalid requiredCount")
        req.requiredCount = rc

    if patch["jobRole"] is not None:
        req.jobRole = str(patch["jobRole"] or "").strip()
    if patch["jobTitle"] is not None:
        req.jobTitle = str(patch["jobTitle"] or "").strip()
    if patch["jd"] is not None:
        req.jd = str(patch["jd"] or "").strip()
    if patch["responsibilities"] is not None:
        req.responsibilities = str(patch["responsibilities"] or "").strip()
    if patch["skills"] is not None:
        req.skills = str(patch["skills"] or "").strip()
    if patch["shift"] is not None:
        req.shift = str(patch["shift"] or "").strip()
    if patch["payScale"] is not None:
        req.payScale = str(patch["payScale"] or "").strip()
    if patch["perks"] is not None:
        req.perks = str(patch["perks"] or "").strip()
    if patch["notes"] is not None:
        req.notes = str(patch["notes"] or "").strip()
    if patch["latestRemark"] is not None:
        req.latestRemark = str(patch["latestRemark"] or "").strip()

    now = iso_utc_now()
    req.updatedAt = now
    req.updatedBy = auth.email

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus=status,
        toStatus=status,
        stageTag="REQ_UPDATED",
        remark="",
        actor=auth,
        meta={},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action="REQUIREMENT_UPDATE",
        fromState=status,
        toState=status,
        stageTag="REQ_UPDATED",
        remark="",
        actor=auth,
        at=now,
        meta={},
    )

    return {"requirementId": requirement_id, "status": status}


def _set_requirement_status(db, requirement_id: str, from_status: str, to_status: str, stage_tag: str, remark: str, auth: AuthContext):
    req = require_requirement(db, requirement_id)

    if str(auth.role or "") == "EA":
        created_by = str(req.createdBy or "").lower()
        if created_by != str(auth.email or "").lower():
            raise ApiError("FORBIDDEN", "Cannot update others requirements")

    current = str(req.status or "").upper()
    if current != from_status:
        raise ApiError("BAD_REQUEST", "Invalid status transition")

    if to_status == "SUBMITTED":
        raised_for = str(req.raisedFor or "").strip()
        concerned_person = str(req.concernedPerson or "").strip()
        required_count = int(req.requiredCount or 0)
        if not raised_for or not concerned_person or required_count <= 0:
            raise ApiError("BAD_REQUEST", "Missing required fields")

    now = iso_utc_now()
    req.status = to_status
    if remark:
        req.latestRemark = remark
    req.updatedAt = now
    req.updatedBy = auth.email

    append_requirement_history(
        db,
        requirementId=requirement_id,
        fromStatus=from_status,
        toStatus=to_status,
        stageTag=stage_tag,
        remark=remark or "",
        actor=auth,
        meta={},
    )
    append_audit(
        db,
        entityType="REQUIREMENT",
        entityId=requirement_id,
        action=stage_tag,
        fromState=from_status,
        toState=to_status,
        stageTag=stage_tag,
        remark=remark or "",
        actor=auth,
        at=now,
        meta={},
    )
    return {"requirementId": requirement_id, "fromStatus": from_status, "toStatus": to_status}


def requirement_submit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    return _set_requirement_status(db, requirement_id, "DRAFT", "SUBMITTED", "REQ_SUBMITTED", "", auth)


def requirement_resubmit(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not remark:
        raise ApiError("BAD_REQUEST", "Missing remark")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    return _set_requirement_status(db, requirement_id, "CLARIFICATION", "SUBMITTED", "REQ_RESUBMITTED", remark, auth)


def requirement_get(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    req = require_requirement(db, requirement_id)
    if str(auth.role or "") == "EA":
        if str(req.createdBy or "").lower() != str(auth.email or "").lower():
            raise ApiError("FORBIDDEN", "Cannot view others requirements")

    return {
        "requirementId": req.requirementId,
        "templateId": req.templateId,
        "jobRole": req.jobRole,
        "jobTitle": req.jobTitle,
        "jd": req.jd,
        "responsibilities": req.responsibilities,
        "skills": req.skills,
        "shift": req.shift,
        "payScale": req.payScale,
        "perks": req.perks,
        "notes": req.notes,
        "raisedFor": req.raisedFor,
        "concernedPerson": req.concernedPerson,
        "requiredCount": req.requiredCount,
        "joinedCount": req.joinedCount,
        "status": req.status,
        "latestRemark": req.latestRemark,
        "createdAt": req.createdAt,
        "createdBy": req.createdBy,
        "updatedAt": req.updatedAt,
        "updatedBy": req.updatedBy,
    }


def hr_requirements_list(data, auth: AuthContext | None, db, cfg):
    tab = str((data or {}).get("tab") or "REVIEW").upper().strip()
    if tab not in {"REVIEW", "PENDING_EA", "APPROVED", "ALL"}:
        tab = "REVIEW"
    count_only = bool((data or {}).get("countOnly"))

    rows = db.execute(select(Requirement)).scalars().all()
    if not rows:
        return {"items": [], "total": 0, "counts": {"review": 0, "pendingEa": 0, "approved": 0}}

    counts = {"review": 0, "pendingEa": 0, "approved": 0}
    included = []
    include_req_ids: list[str] = []

    for r in rows:
        st = str(r.status or "").upper()
        if st == "SUBMITTED":
            counts["review"] += 1
        elif st == "CLARIFICATION":
            counts["pendingEa"] += 1
        elif st == "APPROVED":
            counts["approved"] += 1

        include = False
        if tab == "ALL":
            include = True
        elif tab == "REVIEW":
            include = st == "SUBMITTED"
        elif tab == "PENDING_EA":
            include = st == "CLARIFICATION"
        elif tab == "APPROVED":
            include = st == "APPROVED"

        if not include:
            continue

        included.append(r)
        include_req_ids.append(r.requirementId)

    if count_only:
        return {"items": [], "total": len(included), "counts": counts}

    jobposting_rows = db.execute(select(JobPosting).where(JobPosting.requirementId.in_(include_req_ids))).scalars().all()
    jobposting_state = {}
    for jp in jobposting_rows:
        checklist_state = {"selectedPortals": [], "portals": {}}
        raw = str(jp.checklistStateJson or "").strip()
        if raw:
            try:
                obj = __import__("json").loads(raw)
                if isinstance(obj, dict):
                    checklist_state = obj
            except Exception:
                pass
        jobposting_state[jp.requirementId] = {
            "requirementId": jp.requirementId,
            "status": str(jp.status or ""),
            "checklistState": checklist_state,
            "screenshotUploadId": str(jp.screenshotUploadId or ""),
            "completedAt": jp.completedAt or "",
            "completedBy": str(jp.completedBy or ""),
            "updatedAt": jp.updatedAt or "",
            "updatedBy": str(jp.updatedBy or ""),
        }

    candidates = (
        db.execute(select(Candidate).where(Candidate.requirementId.in_(include_req_ids)))
        .scalars()
        .all()
    )
    by_req: dict[str, list[dict]] = {rid: [] for rid in include_req_ids}
    for c in candidates:
        by_req.setdefault(c.requirementId, []).append(
            {
                "candidateId": c.candidateId,
                "candidateName": c.candidateName,
                "jobRole": c.jobRole,
                "mobile": c.mobile,
                "source": c.source,
                "cvFileId": c.cvFileId,
                "cvFileName": c.cvFileName,
                "status": c.status,
                "holdUntil": c.holdUntil or "",
                "walkinAt": c.walkinAt or "",
                "walkinNotes": c.walkinNotes or "",
                "notPickCount": c.notPickCount or 0,
                "preCallAt": c.preCallAt or "",
                "createdAt": c.createdAt,
                "createdBy": c.createdBy,
            }
        )

    for rid in by_req:
        by_req[rid].sort(key=lambda x: str(x.get("createdAt") or ""), reverse=True)

    items = []
    for r in included:
        rid = r.requirementId
        jp_state = jobposting_state.get(rid)
        items.append(
            {
                "requirementId": rid,
                "templateId": r.templateId,
                "jobRole": r.jobRole,
                "jobTitle": r.jobTitle,
                "raisedFor": r.raisedFor,
                "concernedPerson": r.concernedPerson,
                "requiredCount": r.requiredCount,
                "joinedCount": r.joinedCount,
                "status": r.status,
                "latestRemark": r.latestRemark,
                "createdAt": r.createdAt,
                "createdBy": r.createdBy,
                "updatedAt": r.updatedAt,
                "updatedBy": r.updatedBy,
                "jobPostingStatus": (jp_state and jp_state.get("status")) or None,
                "jobPostingState": jp_state or None,
                "candidateCount": len(by_req.get(rid, [])),
                "candidates": by_req.get(rid, []),
            }
        )

    items.sort(key=lambda x: str(x.get("updatedAt") or ""), reverse=True)
    return {"items": items, "total": len(items), "counts": counts}


def requirement_approve(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    res = _set_requirement_status(db, requirement_id, "SUBMITTED", "APPROVED", "REQ_APPROVED", "", auth)
    # Ensure JobPosting row exists
    _ensure_jobposting_for_requirement(db, requirement_id, auth)
    return res


def requirement_clarification(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not remark:
        raise ApiError("BAD_REQUEST", "Remark required")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")
    return _set_requirement_status(db, requirement_id, "SUBMITTED", "CLARIFICATION", "REQ_CLARIFICATION_REQUESTED", remark, auth)


def requirement_list_by_role(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    tab = str((data or {}).get("tab") or "OPEN").upper().strip()
    if tab not in {"OPEN", "CLARIFICATION", "CLOSED", "ALL"}:
        tab = "OPEN"
    count_only = bool((data or {}).get("countOnly"))

    rows = db.execute(select(Requirement)).scalars().all()
    if not rows:
        return {"items": [], "total": 0, "counts": {"open": 0, "clarification": 0, "closed": 0}}

    items = []
    counts = {"open": 0, "clarification": 0, "closed": 0}
    included_count = 0

    creator_email_lc = str(auth.email or "").lower()
    for r in rows:
        created_by = str(r.createdBy or "").lower()
        if str(auth.role or "") == "EA" and created_by != creator_email_lc:
            continue

        st = str(r.status or "").upper()
        if st == "CLARIFICATION":
            counts["clarification"] += 1
        elif st == "CLOSED":
            counts["closed"] += 1
        else:
            counts["open"] += 1

        include = False
        if tab == "ALL":
            include = True
        elif tab == "CLARIFICATION":
            include = st == "CLARIFICATION"
        elif tab == "CLOSED":
            include = st == "CLOSED"
        elif tab == "OPEN":
            include = st not in {"CLARIFICATION", "CLOSED"}

        if not include:
            continue

        included_count += 1
        if not count_only:
            items.append(
                {
                    "requirementId": r.requirementId,
                    "templateId": r.templateId,
                    "jobRole": r.jobRole,
                    "jobTitle": r.jobTitle,
                    "raisedFor": r.raisedFor,
                    "concernedPerson": r.concernedPerson,
                    "requiredCount": r.requiredCount,
                    "joinedCount": r.joinedCount,
                    "status": r.status,
                    "latestRemark": r.latestRemark,
                    "createdAt": r.createdAt,
                    "createdBy": r.createdBy,
                    "updatedAt": r.updatedAt,
                    "updatedBy": r.updatedBy,
                }
            )

    if count_only:
        return {"items": [], "total": included_count, "counts": counts}

    items.sort(key=lambda x: str(x.get("updatedAt") or ""), reverse=True)
    return {"items": items, "total": len(items), "counts": counts}


def _ensure_jobposting_for_requirement(db, requirement_id: str, auth: AuthContext):
    jp = db.execute(select(JobPosting).where(JobPosting.requirementId == requirement_id)).scalar_one_or_none()
    if jp:
        return
    now = iso_utc_now()
    db.add(
        JobPosting(
            requirementId=requirement_id,
            status="NOT_STARTED",
            checklistStateJson="",
            screenshotUploadId="",
            completedAt="",
            completedBy="",
            updatedAt=now,
            updatedBy=auth.email,
        )
    )
    append_audit(
        db,
        entityType="JOBPOST",
        entityId=requirement_id,
        action="JOBPOST_INIT",
        fromState="",
        toState="NOT_STARTED",
        stageTag="JOBPOST_INIT",
        remark="",
        actor=auth,
        at=now,
        meta="",
    )
