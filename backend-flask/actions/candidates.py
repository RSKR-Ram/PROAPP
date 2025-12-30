from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import select

from actions.candidate_repo import (
    find_candidate,
    has_duplicate_candidate_in_requirement,
    normalize_mobile,
    reject_candidate_with_meta,
    update_candidate,
)
from actions.helpers import append_audit, append_hold_log, append_rejection_log, next_prefixed_id
from actions.jobposting import assert_job_posting_complete
from models import Candidate, RejectionLog, Requirement
from utils import ApiError, AuthContext, decode_base64_to_bytes, iso_utc_now, parse_datetime_maybe, sanitize_filename, to_iso_utc


def _get_requirement_job_role(db, requirement_id: str) -> str:
    req = db.execute(select(Requirement).where(Requirement.requirementId == requirement_id)).scalar_one_or_none()
    if not req:
        raise ApiError("NOT_FOUND", "Requirement not found")
    return str(req.jobRole or "")


def file_upload_cv(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    filename = str((data or {}).get("filename") or "").strip() or "cv"
    mime_type = str((data or {}).get("mimeType") or "").strip() or "application/octet-stream"
    base64 = str((data or {}).get("base64") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not base64:
        raise ApiError("BAD_REQUEST", "Missing base64")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    bytes_ = decode_base64_to_bytes(base64)
    safe_name = sanitize_filename(filename)
    file_id = os.urandom(16).hex()

    os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    out_name = f"CV_{requirement_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{safe_name}"
    out_path = os.path.join(cfg.UPLOAD_DIR, f"{file_id}_{out_name}")
    with open(out_path, "wb") as f:
        f.write(bytes_)

    now = iso_utc_now()
    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=requirement_id,
        action="FILE_UPLOAD_CV",
        fromState="",
        toState="",
        stageTag="FILE_UPLOAD_CV",
        remark=safe_name,
        actor=auth,
        at=now,
        meta={"fileId": file_id, "mimeType": mime_type},
    )

    return {"fileId": file_id, "fileName": safe_name}


def candidate_add(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_name = str((data or {}).get("candidateName") or "").strip()
    mobile = str((data or {}).get("mobile") or "").strip()
    source = str((data or {}).get("source") or "").strip()
    cv_file_id = str((data or {}).get("cvFileId") or "").strip()
    cv_file_name = str((data or {}).get("cvFileName") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_name:
        raise ApiError("BAD_REQUEST", "Missing candidateName")
    if not mobile:
        raise ApiError("BAD_REQUEST", "Missing mobile")
    if not cv_file_id:
        raise ApiError("BAD_REQUEST", "Missing cvFileId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    job_role = _get_requirement_job_role(db, requirement_id)

    norm_mobile = normalize_mobile(mobile)
    if not norm_mobile:
        raise ApiError("BAD_REQUEST", "Invalid mobile")

    if has_duplicate_candidate_in_requirement(
        db, requirement_id=requirement_id, norm_mobile=norm_mobile, candidate_name=candidate_name
    ):
        raise ApiError("CONFLICT", "Candidate already exists (same name and mobile) in this requirement")

    existing_ids = [x for x in db.execute(select(Candidate.candidateId)).scalars().all()]
    candidate_id = next_prefixed_id(db, counter_key="CND", prefix="CND-", pad=5, existing_ids=existing_ids)

    now = iso_utc_now()
    db.add(
        Candidate(
            candidateId=candidate_id,
            requirementId=requirement_id,
            candidateName=candidate_name,
            jobRole=job_role,
            mobile=mobile,
            source=source,
            cvFileId=cv_file_id,
            cvFileName=cv_file_name,
            status="NEW",
            notPickCount=0,
            createdAt=now,
            createdBy=auth.email,
            updatedAt=now,
            updatedBy=auth.email,
        )
    )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="CANDIDATE_ADD",
        fromState="",
        toState="NEW",
        stageTag="CANDIDATE_ADD",
        remark="",
        actor=auth,
        at=now,
        meta={"requirementId": requirement_id},
    )

    return {"candidateId": candidate_id}


def candidate_bulk_add(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    items = (data or {}).get("items") or []

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not isinstance(items, list):
        raise ApiError("BAD_REQUEST", "items must be an array")
    if len(items) > 50:
        raise ApiError("BAD_REQUEST", "Max 50 files")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    assert_job_posting_complete(db, requirement_id)

    job_role = _get_requirement_job_role(db, requirement_id)

    existing = db.execute(select(Candidate).where(Candidate.requirementId == requirement_id)).scalars().all()
    existing_keys = set()
    for c in existing:
        m0 = normalize_mobile(c.mobile)
        if not m0:
            continue
        k0 = f"{m0}|{str(c.candidateName or '').strip().upper()}"
        if k0 and k0 != "|":
            existing_keys.add(k0)

    now = iso_utc_now()
    created = []
    errors = []

    existing_ids = [x for x in db.execute(select(Candidate.candidateId)).scalars().all()]
    ids_pool = list(existing_ids)

    for i, it in enumerate(items):
        it = it or {}
        candidate_name = str(it.get("candidateName") or "").strip()
        mobile = str(it.get("mobile") or "").strip()
        source = str(it.get("source") or "").strip()
        cv_file_id = str(it.get("cvFileId") or "").strip()
        cv_file_name = str(it.get("cvFileName") or "").strip()

        if not candidate_name or not mobile or not cv_file_id:
            errors.append({"index": i, "message": "Missing candidateName/mobile/cvFileId"})
            continue

        norm_mobile = normalize_mobile(mobile)
        if not norm_mobile:
            errors.append({"index": i, "message": "Invalid mobile"})
            continue

        cand_key = f"{norm_mobile}|{candidate_name.strip().upper()}"
        if cand_key in existing_keys:
            errors.append({"index": i, "message": "Duplicate candidate (same name and mobile) in requirement"})
            continue
        existing_keys.add(cand_key)

        candidate_id = next_prefixed_id(db, counter_key="CND", prefix="CND-", pad=5, existing_ids=ids_pool)
        ids_pool.append(candidate_id)

        db.add(
            Candidate(
                candidateId=candidate_id,
                requirementId=requirement_id,
                candidateName=candidate_name,
                jobRole=job_role,
                mobile=mobile,
                source=source,
                cvFileId=cv_file_id,
                cvFileName=cv_file_name,
                status="NEW",
                notPickCount=0,
                createdAt=now,
                createdBy=auth.email,
                updatedAt=now,
                updatedBy=auth.email,
            )
        )

        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="CANDIDATE_ADD",
            fromState="",
            toState="NEW",
            stageTag="CANDIDATE_ADD",
            remark="BULK",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id},
        )

        created.append({"candidateId": candidate_id})

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=requirement_id,
        action="CANDIDATE_BULK_ADD",
        fromState="",
        toState="",
        stageTag="CANDIDATE_BULK_ADD",
        remark="",
        actor=auth,
        at=now,
        meta={"created": len(created), "errors": len(errors)},
    )

    return {"created": created, "errors": errors}


def shortlist_decide(data, auth: AuthContext | None, db, cfg):
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

    if current_status in {"OWNER", "OWNER_HOLD"}:
        raise ApiError("BAD_REQUEST", "Candidate is locked in Owner tab")

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        append_rejection_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            stageTag="Shortlisting",
            remark=remark,
            actor=auth,
        )
        update_candidate(db, cand=cand, patch={"status": "REJECTED", "holdUntil": ""}, auth=auth)
        return {"ok": True, "status": "REJECTED"}

    if decision == "HOLD":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        append_hold_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            action="HOLD",
            stageTag="Shortlisting Hold",
            remark=remark,
            actor=auth,
            holdUntil="",
        )
        update_candidate(db, cand=cand, patch={"status": "HOLD", "holdUntil": ""}, auth=auth)
        return {"ok": True, "status": "HOLD"}

    if decision == "OWNER_SEND":
        update_candidate(db, cand=cand, patch={"status": "OWNER", "holdUntil": ""}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="OWNER_SEND",
            fromState=current_status,
            toState="OWNER",
            stageTag="SHORTLIST_OWNER_SEND",
            remark="",
            actor=auth,
            at=iso_utc_now(),
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": "OWNER"}

    raise ApiError("BAD_REQUEST", "Invalid decision")


def shortlist_hold_revert(data, auth: AuthContext | None, db, cfg):
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
    if str(cand.status or "").upper() != "HOLD":
        raise ApiError("BAD_REQUEST", "Candidate not in HOLD")

    append_hold_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        action="REVERT",
        stageTag="Shortlisting Hold",
        remark=remark or "Revert",
        actor=auth,
        holdUntil="",
    )
    update_candidate(db, cand=cand, patch={"status": "NEW", "holdUntil": ""}, auth=auth)
    return {"ok": True, "status": "NEW"}


def hold_revert(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    role = str(auth.role or "").upper()
    if role not in {"OWNER", "EA", "ADMIN"}:
        raise ApiError("FORBIDDEN", "Not allowed")

    assert_job_posting_complete(db, requirement_id)

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    if str(cand.status or "").upper() != "OWNER_HOLD":
        raise ApiError("BAD_REQUEST", "Candidate not in OWNER_HOLD")

    append_hold_log(
        db,
        candidateId=candidate_id,
        requirementId=requirement_id,
        action="REVERT",
        stageTag="Owner Hold",
        remark=remark or "Revert",
        actor=auth,
        holdUntil="",
    )
    update_candidate(db, cand=cand, patch={"status": "OWNER", "holdUntil": ""}, auth=auth)
    return {"ok": True, "status": "OWNER"}


def owner_candidates_list(data, auth: AuthContext | None, db, cfg):
    count_only = bool((data or {}).get("countOnly"))

    req_map = {}
    if not count_only:
        reqs = db.execute(select(Requirement.requirementId, Requirement.jobTitle, Requirement.jobRole)).all()
        req_map = {rid: {"jobTitle": jt or "", "jobRole": jr or ""} for rid, jt, jr in reqs}

    rows = (
        db.execute(select(Candidate).where(Candidate.status.in_(["OWNER", "OWNER_HOLD", "FINAL_OWNER_PENDING"])))
        .scalars()
        .all()
    )
    if not rows:
        return {"items": [], "total": 0} if count_only else {"items": [], "total": 0}

    approvals_count = 0
    final_count = 0
    items = []

    for c in rows:
        status = str(c.status or "").upper()
        if status in {"OWNER", "OWNER_HOLD"}:
            approvals_count += 1
        if status == "FINAL_OWNER_PENDING":
            final_count += 1
        if count_only:
            continue

        rm = req_map.get(c.requirementId, {})
        selected_tests = []
        raw = str(c.techSelectedTestsJson or "").strip()
        if raw:
            try:
                selected_tests = json.loads(raw)
            except Exception:
                selected_tests = []

        items.append(
            {
                "candidateId": c.candidateId,
                "requirementId": c.requirementId,
                "candidateName": c.candidateName,
                "jobRole": c.jobRole,
                "jobTitle": rm.get("jobTitle", ""),
                "mobile": c.mobile,
                "source": c.source,
                "cvFileId": c.cvFileId,
                "cvFileName": c.cvFileName,
                "status": c.status,
                "holdUntil": c.holdUntil or "",
                "onlineTestScore": c.onlineTestScore or "",
                "onlineTestResult": c.onlineTestResult or "",
                "testDecisionsJson": c.testDecisionsJson or "",
                "candidate_test_failed_but_manually_continued": c.candidate_test_failed_but_manually_continued or False,
                "preInterviewMarks": c.preInterviewMarks or "",
                "inPersonMarks": c.inPersonMarks or "",
                "techSelectedTests": selected_tests,
                "tallyMarks": c.tallyMarks or "",
                "voiceMarks": c.voiceMarks or "",
                "techReview": c.techReview or "",
                "excelMarks": c.excelMarks or "",
                "excelReview": c.excelReview or "",
                "techResult": c.techResult or "",
                "techEvaluatedAt": c.techEvaluatedAt or "",
                "finalHoldAt": c.finalHoldAt or "",
                "finalHoldRemark": c.finalHoldRemark or "",
                "createdAt": c.createdAt or "",
                "createdBy": c.createdBy or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
            }
        )

    items.sort(key=lambda x: str(x.get("updatedAt") or ""), reverse=True)

    if count_only:
        return {"items": [], "total": approvals_count + final_count, "counts": {"approvals": approvals_count, "final": final_count}}

    return {"items": items, "total": len(items)}


def owner_final_decide(data, auth: AuthContext | None, db, cfg):
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
    if current_status != "FINAL_OWNER_PENDING":
        raise ApiError("BAD_REQUEST", "Candidate not pending Owner final")

    now = iso_utc_now()

    if decision == "SELECT":
        update_candidate(db, cand=cand, patch={"status": "SELECTED"}, auth=auth)
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="OWNER_FINAL_DECIDE",
            fromState=current_status,
            toState="SELECTED",
            stageTag="Final Select",
            remark=remark or "",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": "SELECTED"}

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        rej = reject_candidate_with_meta(
            db,
            candidate_id=candidate_id,
            requirement_id=requirement_id,
            stage_tag="Final Owner Reject",
            remark=remark,
            reason_code="FINAL_OWNER_REJECT",
            auth=auth,
        )
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="OWNER_FINAL_DECIDE",
            fromState=current_status,
            toState="REJECTED",
            stageTag="Final Owner Reject",
            remark=remark,
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id, "reasonCode": "FINAL_OWNER_REJECT"},
        )
        return rej

    if decision == "HOLD":
        append_hold_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            action="HOLD",
            stageTag="Final Hold",
            remark=remark or "Hold",
            actor=auth,
            holdUntil="",
        )
        update_candidate(
            db,
            cand=cand,
            patch={"status": "FINAL_HOLD", "finalHoldAt": "", "finalHoldRemark": remark or ""},
            auth=auth,
        )
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="OWNER_FINAL_DECIDE",
            fromState=current_status,
            toState="FINAL_HOLD",
            stageTag="Final Hold",
            remark=remark or "",
            actor=auth,
            at=now,
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": "FINAL_HOLD"}

    raise ApiError("BAD_REQUEST", "Invalid decision")


def rejection_log_list(data, auth: AuthContext | None, db, cfg):
    reqs = db.execute(select(Requirement.requirementId, Requirement.jobTitle, Requirement.jobRole)).all()
    req_map = {rid: {"jobTitle": jt or "", "jobRole": jr or ""} for rid, jt, jr in reqs}

    logs = db.execute(select(RejectionLog)).scalars().all()
    logs_by_key: dict[str, list[dict]] = {}
    for l in logs:
        cid = str(l.candidateId or "").strip()
        rid = str(l.requirementId or "").strip()
        if not cid or not rid:
            continue
        k = f"{cid}|{rid}"
        logs_by_key.setdefault(k, []).append(
            {
                "logId": l.logId or "",
                "at": l.at or "",
                "stageTag": l.stageTag or "",
                "remark": l.remark or "",
                "actorRole": l.actorRole or "",
                "actorUserId": l.actorUserId or "",
                "rejectionType": l.rejectionType or "",
                "autoRejectCode": l.autoRejectCode or "",
            }
        )
    for k in logs_by_key:
        logs_by_key[k].sort(key=lambda x: str(x.get("at") or ""), reverse=True)

    cands = db.execute(select(Candidate).where(Candidate.status == "REJECTED")).scalars().all()
    items = []
    for c in cands:
        cid = str(c.candidateId or "").strip()
        rid = str(c.requirementId or "").strip()
        if not cid or not rid:
            continue
        rm = req_map.get(rid, {})
        job_role = str(c.jobRole or rm.get("jobRole", "")).strip()

        key2 = f"{cid}|{rid}"
        logs2 = logs_by_key.get(key2, [])
        latest = logs2[0] if logs2 else None

        items.append(
            {
                "candidateId": cid,
                "requirementId": rid,
                "candidateName": c.candidateName or "",
                "mobile": c.mobile or "",
                "source": c.source or "",
                "jobRole": job_role,
                "jobTitle": rm.get("jobTitle", ""),
                "status": c.status or "",
                "rejectedFromStatus": c.rejectedFromStatus or "",
                "rejectedReasonCode": c.rejectedReasonCode or "",
                "rejectedAt": c.rejectedAt or "",
                "updatedAt": c.updatedAt or "",
                "updatedBy": c.updatedBy or "",
                "rejectedStageTag": (latest or {}).get("stageTag", "") if latest else "",
                "rejectedRemark": (latest or {}).get("remark", "") if latest else "",
                "rejectedActorRole": (latest or {}).get("actorRole", "") if latest else "",
                "rejectedActorUserId": (latest or {}).get("actorUserId", "") if latest else "",
                "rejectionType": (latest or {}).get("rejectionType", "") if latest else "",
                "autoRejectCode": (latest or {}).get("autoRejectCode", "") if latest else "",
                "logs": logs2,
            }
        )

    items.sort(key=lambda x: str(x.get("rejectedAt") or ""), reverse=True)
    return {"items": items, "total": len(items)}


def reject_revert(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    remark = str((data or {}).get("remark") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not candidate_id:
        raise ApiError("BAD_REQUEST", "Missing candidateId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    cand = find_candidate(db, candidate_id=candidate_id, requirement_id=requirement_id)
    status = str(cand.status or "").upper()
    if status != "REJECTED":
        raise ApiError("BAD_REQUEST", "Candidate not rejected")

    prev = str(cand.rejectedFromStatus or "").upper()
    reason = str(cand.rejectedReasonCode or "").upper()
    if not prev:
        raise ApiError("BAD_REQUEST", "Cannot revert (missing previous status)")

    role = str(auth.role or "").upper()
    allow = False
    if reason in {"ONLINE_TEST_FAIL", "ONLINE_TEST_FAIL_MANUAL"}:
        allow = role in {"ADMIN", "OWNER", "EA"}
    elif reason in {"TECH_FAIL", "TECH_FAIL_MANUAL"}:
        allow = role in {"ADMIN", "OWNER", "EA", "HR"}
    elif reason in {"INPERSON_LOW", "INPERSON_FAIL_MANUAL"}:
        allow = role in {"ADMIN", "OWNER", "EA"}
    else:
        allow = role == "ADMIN"

    if not allow:
        raise ApiError("FORBIDDEN", "Not allowed to revert this rejection")

    update_candidate(
        db,
        cand=cand,
        patch={"status": prev, "rejectedFromStatus": "", "rejectedReasonCode": "", "rejectedAt": ""},
        auth=auth,
    )

    append_audit(
        db,
        entityType="CANDIDATE",
        entityId=candidate_id,
        action="REJECT_REVERT",
        fromState="REJECTED",
        toState=prev,
        stageTag="Reject Revert",
        remark=remark,
        actor=auth,
        at=iso_utc_now(),
        meta={"requirementId": requirement_id, "reason": reason},
    )
    return {"ok": True, "status": prev}


def owner_decide(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    candidate_id = str((data or {}).get("candidateId") or "").strip()
    decision = str((data or {}).get("decision") or "").upper().strip()
    remark = str((data or {}).get("remark") or "").strip()
    hold_until_iso = str((data or {}).get("holdUntil") or "").strip()

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
    if current_status not in {"OWNER", "OWNER_HOLD"}:
        raise ApiError("BAD_REQUEST", "Candidate not in Owner tab")

    if decision == "REJECT":
        if not remark:
            raise ApiError("BAD_REQUEST", "Remark required")
        append_rejection_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            stageTag="Owner Rejected before Walk-in",
            remark=remark,
            actor=auth,
        )
        update_candidate(db, cand=cand, patch={"status": "REJECTED", "holdUntil": ""}, auth=auth)
        return {"ok": True, "status": "REJECTED"}

    if decision == "HOLD":
        if not hold_until_iso:
            raise ApiError("BAD_REQUEST", "Missing holdUntil")
        dt = parse_datetime_maybe(hold_until_iso, app_timezone=cfg.APP_TIMEZONE)
        if not dt:
            raise ApiError("BAD_REQUEST", "Invalid holdUntil")
        hold_until = to_iso_utc(dt)

        append_hold_log(
            db,
            candidateId=candidate_id,
            requirementId=requirement_id,
            action="HOLD",
            stageTag="Owner Hold",
            remark=remark or "Hold",
            actor=auth,
            holdUntil=hold_until,
        )
        update_candidate(db, cand=cand, patch={"status": "OWNER_HOLD", "holdUntil": hold_until}, auth=auth)
        return {"ok": True, "status": "OWNER_HOLD", "holdUntil": hold_until}

    if decision == "APPROVE_WALKIN":
        update_candidate(
            db,
            cand=cand,
            patch={
                "status": "WALKIN_PENDING",
                "holdUntil": "",
                "walkinAt": "",
                "walkinNotes": "",
                "notPickCount": 0,
                "preCallAt": "",
            },
            auth=auth,
        )
        append_audit(
            db,
            entityType="CANDIDATE",
            entityId=candidate_id,
            action="APPROVE_WALKIN",
            fromState=current_status,
            toState="WALKIN_PENDING",
            stageTag="OWNER_APPROVE_WALKIN",
            remark="",
            actor=auth,
            at=iso_utc_now(),
            meta={"requirementId": requirement_id},
        )
        return {"ok": True, "status": "WALKIN_PENDING"}

    raise ApiError("BAD_REQUEST", "Invalid decision")
