from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import func, select

from actions.helpers import next_prefixed_id
from models import AssignedTraining, Candidate, Employee, TrainingLog, TrainingMaster
from utils import ApiError, AuthContext, iso_utc_now, normalize_role, parse_datetime_maybe, safe_json_string, to_iso_utc


def _normalize_training_status(status: str) -> str:
    s = str(status or "").upper().strip()
    if s in {"IN-PROGRESS", "INPROGRESS"}:
        s = "IN_PROGRESS"
    if not s:
        return "PENDING"
    if s not in {"PENDING", "IN_PROGRESS", "COMPLETED", "OVERDUE"}:
        return "PENDING"
    return s


def _compute_overdue(status: str, due_date_iso: str, now: datetime) -> str:
    st = _normalize_training_status(status)
    if st == "COMPLETED":
        return "COMPLETED"
    due_dt = parse_datetime_maybe(due_date_iso) if due_date_iso else None
    if not due_dt:
        return st
    if due_dt < now and st in {"PENDING", "IN_PROGRESS"}:
        return "OVERDUE"
    return st


def _parse_documents_lines(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x or "").strip() for x in raw if str(x or "").strip()]
    s = str(raw or "")
    out = []
    for line in s.splitlines():
        line = str(line or "").strip()
        if line:
            out.append(line)
    return out


def _read_training_master_map(db):
    rows = db.execute(select(TrainingMaster)).scalars().all()
    items = []
    by_id = {}
    for r in rows:
        tid = str(r.training_id or "").strip()
        if not tid:
            continue
        docs = []
        raw = str(r.documentsJson or "").strip()
        if raw:
            try:
                docs = json.loads(raw) or []
            except Exception:
                docs = []
        if not isinstance(docs, list):
            docs = []
        obj = {
            "training_id": tid,
            "name": r.name or "",
            "department": r.department or "",
            "description": r.description or "",
            "video_link": r.video_link or "",
            "documents": docs,
            "created_by": r.created_by or "",
            "created_on": r.created_on or "",
        }
        items.append(obj)
        by_id[tid] = obj
    items.sort(key=lambda x: str(x.get("name") or ""))
    return {"items": items, "byId": by_id}


def training_master_list(data, auth: AuthContext | None, db, cfg):
    dept = str((data or {}).get("department") or "").strip()
    res = _read_training_master_map(db)
    if not dept:
        return {"items": res["items"]}
    dept_u = dept.upper()
    filtered = [x for x in res["items"] if str(x.get("department") or "").upper() == dept_u]
    return {"items": filtered}


def training_master_upsert(data, auth: AuthContext | None, db, cfg):
    training_id = str((data or {}).get("training_id") or (data or {}).get("trainingId") or "").strip()
    name = str((data or {}).get("name") or (data or {}).get("training_name") or "").strip()
    department = str((data or {}).get("department") or "").strip()
    description = str((data or {}).get("description") or "").strip()
    video_link = str((data or {}).get("video_link") or (data or {}).get("videoLink") or "").strip()
    documents = _parse_documents_lines((data or {}).get("documents") or (data or {}).get("documentsLines"))

    if not name:
        raise ApiError("BAD_REQUEST", "Missing training name")
    if not department:
        raise ApiError("BAD_REQUEST", "Missing department")

    now = iso_utc_now()
    actor = str((auth.email or auth.userId) if auth else "")

    if not training_id:
        existing_ids = [x for x in db.execute(select(TrainingMaster.training_id)).scalars().all()]
        training_id = next_prefixed_id(db, counter_key="TRN", prefix="TRN-", pad=5, existing_ids=existing_ids)
        db.add(
            TrainingMaster(
                training_id=training_id,
                name=name,
                department=department,
                description=description,
                video_link=video_link,
                documentsJson=safe_json_string(documents, "[]"),
                created_by=actor,
                created_on=now,
            )
        )
        db.add(
            TrainingLog(
                timestamp=now,
                candidate_id="",
                training_id=training_id,
                assigned_id="",
                action="TRAINING_TEMPLATE_CREATE",
                performed_by=actor,
                remarks="",
                metaJson=safe_json_string({"name": name, "department": department}, "{}"),
            )
        )
        return {"training_id": training_id}

    tpl = db.execute(select(TrainingMaster).where(TrainingMaster.training_id == training_id)).scalar_one_or_none()
    if not tpl:
        raise ApiError("NOT_FOUND", "Training not found")

    tpl.name = name
    tpl.department = department
    tpl.description = description
    tpl.video_link = video_link
    tpl.documentsJson = safe_json_string(documents, "[]")

    db.add(
        TrainingLog(
            timestamp=now,
            candidate_id="",
            training_id=training_id,
            assigned_id="",
            action="TRAINING_TEMPLATE_UPDATE",
            performed_by=actor,
            remarks="",
            metaJson=safe_json_string({"name": name, "department": department}, "{}"),
        )
    )
    return {"training_id": training_id}


def training_assign(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    training_id = str((data or {}).get("training_id") or (data or {}).get("trainingId") or "").strip()
    due_raw = (data or {}).get("due_date") or (data or {}).get("dueDate") or ""
    due_dt = parse_datetime_maybe(due_raw, app_timezone=cfg.APP_TIMEZONE)

    override_video = str((data or {}).get("video_link") or (data or {}).get("videoLink") or "").strip()
    override_description = str((data or {}).get("description") or "").strip()
    documents = _parse_documents_lines((data or {}).get("documents") or (data or {}).get("documentsLines"))

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")
    if not training_id:
        raise ApiError("BAD_REQUEST", "Missing training_id")
    if not due_dt:
        raise ApiError("BAD_REQUEST", "Missing due_date")

    actor = str((auth.email or auth.userId) if auth else "")

    master = _read_training_master_map(db)
    tpl = master["byId"].get(training_id)
    if not tpl:
        raise ApiError("NOT_FOUND", "Training template not found")

    now = iso_utc_now()
    existing_ids = [x for x in db.execute(select(AssignedTraining.assigned_id)).scalars().all()]
    assigned_id = next_prefixed_id(db, counter_key="ASN", prefix="ASN-", pad=6, existing_ids=existing_ids)

    docs = documents if documents else (tpl.get("documents") or [])
    due_iso = to_iso_utc(due_dt)

    db.add(
        AssignedTraining(
            assigned_id=assigned_id,
            candidate_id=candidate_id,
            training_id=training_id,
            training_name=tpl.get("name") or "",
            department=tpl.get("department") or "",
            description=override_description or tpl.get("description") or "",
            video_link=override_video or tpl.get("video_link") or "",
            documentsJson=safe_json_string(docs, "[]"),
            status="PENDING",
            assigned_date=now,
            due_date=due_iso,
            start_time="",
            completion_time="",
            assigned_by=actor,
        )
    )

    db.add(
        TrainingLog(
            timestamp=now,
            candidate_id=candidate_id,
            training_id=training_id,
            assigned_id=assigned_id,
            action="ASSIGN",
            performed_by=actor,
            remarks="",
            metaJson=safe_json_string({"due_date": due_iso, "template": {"name": tpl.get("name"), "department": tpl.get("department")}}, "{}"),
        )
    )
    return {"assigned_id": assigned_id, "status": "PENDING"}


def training_list(data, auth: AuthContext | None, db, cfg):
    requested_candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    role = normalize_role(auth.role if auth else "")

    candidate_id = requested_candidate_id
    if role == "EMPLOYEE":
        emp_id = str(auth.userId or "").strip() if auth else ""
        emp = db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee missing")
        candidate_id = str(emp.candidateId or "").strip()
        if requested_candidate_id and requested_candidate_id != candidate_id:
            raise ApiError("FORBIDDEN", "Candidate mismatch")

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")

    rows = db.execute(select(AssignedTraining).where(AssignedTraining.candidate_id == candidate_id)).scalars().all()
    if not rows:
        return {"items": []}

    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    out = []

    for row in rows:
        status_norm = _normalize_training_status(row.status)
        effective = _compute_overdue(status_norm, row.due_date, now_dt)
        if effective != status_norm:
            # Persist overdue transition
            row.status = effective
            db.add(
                TrainingLog(
                    timestamp=now_iso,
                    candidate_id=candidate_id,
                    training_id=str(row.training_id or ""),
                    assigned_id=str(row.assigned_id or ""),
                    action="AUTO_OVERDUE",
                    performed_by="SYSTEM",
                    remarks="",
                    metaJson=safe_json_string({"from": status_norm, "to": effective}, "{}"),
                )
            )

        docs = []
        raw_docs = str(row.documentsJson or "").strip()
        if raw_docs:
            try:
                docs = json.loads(raw_docs) or []
            except Exception:
                docs = []
        if not isinstance(docs, list):
            docs = []

        out.append(
            {
                "assigned_id": row.assigned_id,
                "candidate_id": candidate_id,
                "training_id": row.training_id,
                "training_name": row.training_name or "",
                "department": row.department or "",
                "description": row.description or "",
                "video_link": row.video_link or "",
                "documents": docs,
                "status": effective,
                "assigned_date": row.assigned_date or "",
                "due_date": row.due_date or "",
                "start_time": row.start_time or "",
                "completion_time": row.completion_time or "",
                "assigned_by": row.assigned_by or "",
            }
        )

    out.sort(key=lambda x: str(x.get("assigned_date") or ""), reverse=True)
    return {"items": out}


def training_status_update(data, auth: AuthContext | None, db, cfg):
    requested_candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    assigned_id = str((data or {}).get("assigned_id") or (data or {}).get("assignedId") or "").strip()
    op = str((data or {}).get("op") or "").upper().strip()
    status_in = str((data or {}).get("status") or "").upper().strip()
    remark = str((data or {}).get("remarks") or (data or {}).get("remark") or "").strip()

    role = normalize_role(auth.role if auth else "")
    candidate_id = requested_candidate_id
    if role == "EMPLOYEE":
        emp_id = str(auth.userId or "").strip() if auth else ""
        emp = db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one_or_none()
        if not emp or not emp.candidateId:
            raise ApiError("AUTH_INVALID", "Employee missing")
        candidate_id = str(emp.candidateId or "").strip()
        if requested_candidate_id and requested_candidate_id != candidate_id:
            raise ApiError("FORBIDDEN", "Candidate mismatch")

    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")
    if not assigned_id:
        raise ApiError("BAD_REQUEST", "Missing assigned_id")

    if op:
        if op in {"START", "RESUME", "OPEN"}:
            next_status = "IN_PROGRESS"
        elif op in {"COMPLETE", "MARK_COMPLETE"}:
            next_status = "COMPLETED"
        else:
            raise ApiError("BAD_REQUEST", "Invalid op")
    else:
        next_status = _normalize_training_status(status_in)
        if next_status not in {"IN_PROGRESS", "COMPLETED"}:
            raise ApiError("BAD_REQUEST", "Status can be IN_PROGRESS or COMPLETED")

    row = (
        db.execute(select(AssignedTraining).where(AssignedTraining.assigned_id == assigned_id).where(AssignedTraining.candidate_id == candidate_id))
        .scalars()
        .first()
    )
    if not row:
        raise ApiError("NOT_FOUND", "Assigned training not found")

    now_dt = datetime.now(timezone.utc)
    now_iso = iso_utc_now()
    actor = str((auth.email or auth.userId) if auth else "")

    current = _normalize_training_status(row.status)
    current = _compute_overdue(current, row.due_date, now_dt)

    if next_status == "IN_PROGRESS":
        row.status = "IN_PROGRESS"
        if not row.start_time:
            row.start_time = now_iso
    elif next_status == "COMPLETED":
        row.status = "COMPLETED"
        if not row.start_time:
            row.start_time = now_iso
        if not row.completion_time:
            row.completion_time = now_iso

    db.add(
        TrainingLog(
            timestamp=now_iso,
            candidate_id=candidate_id,
            training_id=str(row.training_id or ""),
            assigned_id=assigned_id,
            action="IN_PROGRESS" if next_status == "IN_PROGRESS" else "COMPLETED",
            performed_by=actor,
            remarks=remark,
            metaJson=safe_json_string({"from": current, "to": next_status}, "{}"),
        )
    )
    return {"assigned_id": assigned_id, "status": str(row.status or "")}


def training_summary(data, auth: AuthContext | None, db, cfg):
    candidate_id = str((data or {}).get("candidate_id") or (data or {}).get("candidateId") or "").strip()
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidate_id")
    res = training_list({"candidate_id": candidate_id}, auth, db, cfg)
    items = res.get("items") or []
    counts = {"TOTAL": 0, "PENDING": 0, "IN_PROGRESS": 0, "COMPLETED": 0, "OVERDUE": 0}
    for it in items:
        s = _normalize_training_status(it.get("status"))
        counts["TOTAL"] += 1
        if s in counts:
            counts[s] += 1
    return {"candidate_id": candidate_id, "counts": counts, "items": items}


def training_dashboard(data, auth: AuthContext | None, db, cfg):
    scope = str((data or {}).get("scope") or "PROBATION").upper().strip()
    now_dt = datetime.now(timezone.utc)

    probation_candidate_map = {}
    if scope == "PROBATION":
        cands = db.execute(select(Candidate).where(Candidate.status == "PROBATION")).scalars().all()
        for c in cands:
            cid = str(c.candidateId or "").strip()
            if not cid:
                continue
            probation_candidate_map[cid] = {
                "candidate_id": cid,
                "candidate_name": c.candidateName or "",
                "jobRole": c.jobRole or "",
                "mobile": c.mobile or "",
                "requirementId": c.requirementId or "",
            }

    rows = db.execute(select(AssignedTraining)).scalars().all()
    if not rows:
        return {"totals": {"TOTAL": 0, "PENDING": 0, "IN_PROGRESS": 0, "COMPLETED": 0, "OVERDUE": 0}, "candidates": []}

    totals = {"TOTAL": 0, "PENDING": 0, "IN_PROGRESS": 0, "COMPLETED": 0, "OVERDUE": 0}
    by_candidate: dict[str, dict] = {}

    for row in rows:
        cid2 = str(row.candidate_id or "").strip()
        if not cid2:
            continue
        if scope == "PROBATION" and cid2 not in probation_candidate_map:
            continue

        st2 = _compute_overdue(row.status, row.due_date, now_dt)
        st2 = _normalize_training_status(st2)

        totals["TOTAL"] += 1
        if st2 in totals:
            totals[st2] += 1

        if cid2 not in by_candidate:
            base = probation_candidate_map.get(cid2, {"candidate_id": cid2})
            by_candidate[cid2] = {
                "candidate_id": cid2,
                "candidate_name": base.get("candidate_name", ""),
                "jobRole": base.get("jobRole", ""),
                "mobile": base.get("mobile", ""),
                "requirementId": base.get("requirementId", ""),
                "TOTAL": 0,
                "PENDING": 0,
                "IN_PROGRESS": 0,
                "COMPLETED": 0,
                "OVERDUE": 0,
            }

        by_candidate[cid2]["TOTAL"] += 1
        if st2 in by_candidate[cid2]:
            by_candidate[cid2][st2] += 1

    candidates = list(by_candidate.values())
    candidates.sort(
        key=lambda x: (
            -(x.get("OVERDUE") or 0),
            -(x.get("PENDING") or 0),
            str(x.get("candidate_name") or x.get("candidate_id") or ""),
        )
    )
    return {"totals": totals, "candidates": candidates, "scope": scope}
