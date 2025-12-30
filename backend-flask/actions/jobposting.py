from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import select

from actions.helpers import append_audit
from models import JobPosting
from utils import ApiError, AuthContext, decode_base64_to_bytes, iso_utc_now, sanitize_filename


def jobpost_init(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    ensure_job_posting_for_requirement(db, requirement_id, auth)
    state = get_job_posting_state(db, requirement_id)
    return state


def jobpost_set_portals(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    portals = (data or {}).get("portals") or []
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not isinstance(portals, list):
        raise ApiError("BAD_REQUEST", "portals must be an array")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    state = get_job_posting_state(db, requirement_id)
    if not state:
        ensure_job_posting_for_requirement(db, requirement_id, auth)
        state = get_job_posting_state(db, requirement_id)

    if str(state.get("status") or "").upper() == "COMPLETE":
        raise ApiError("BAD_REQUEST", "JobPosting already complete")

    normalized = normalize_portals(portals)
    if not normalized:
        raise ApiError("BAD_REQUEST", "Select at least one portal")

    next_state = merge_portals_into_checklist_state(state.get("checklistState"), normalized)

    now = iso_utc_now()
    update_job_posting_row(
        db,
        requirement_id,
        {
            "status": "IN_PROGRESS",
            "checklistState": next_state,
            "updatedAt": now,
            "updatedBy": auth.email,
        },
    )

    append_audit(
        db,
        entityType="JOBPOST",
        entityId=requirement_id,
        action="JOBPOST_SET_PORTALS",
        fromState=state.get("status") or "",
        toState="IN_PROGRESS",
        stageTag="JOBPOST_SET_PORTALS",
        remark="",
        actor=auth,
        at=now,
        meta={"portals": normalized},
    )

    return get_job_posting_state(db, requirement_id)


def jobpost_upload_screenshot(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    portal_key = str((data or {}).get("portalKey") or "").strip()
    filename = str((data or {}).get("filename") or "").strip() or "screenshot"
    mime_type = str((data or {}).get("mimeType") or "").strip() or "application/octet-stream"
    base64 = str((data or {}).get("base64") or "").strip()

    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not portal_key:
        raise ApiError("BAD_REQUEST", "Missing portalKey")
    if not base64:
        raise ApiError("BAD_REQUEST", "Missing base64")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    state = get_job_posting_state(db, requirement_id)
    if not state:
        raise ApiError("NOT_FOUND", "JobPosting not initialized")
    if str(state.get("status") or "").upper() == "COMPLETE":
        raise ApiError("BAD_REQUEST", "JobPosting already complete")

    checklist = state.get("checklistState") or {"selectedPortals": [], "portals": {}}
    portals_map = checklist.get("portals") if isinstance(checklist, dict) else None
    if not isinstance(portals_map, dict) or portal_key not in portals_map:
        raise ApiError("BAD_REQUEST", f"Portal not selected: {portal_key}")

    bytes_ = decode_base64_to_bytes(base64)
    safe_name = sanitize_filename(filename)
    file_id = os.urandom(16).hex()

    os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    out_name = f"JOBPOST_{requirement_id}_{portal_key}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{safe_name}"
    out_path = os.path.join(cfg.UPLOAD_DIR, f"{file_id}_{out_name}")
    with open(out_path, "wb") as f:
        f.write(bytes_)

    p = portals_map.get(portal_key) or {}
    if not isinstance(p, dict):
        p = {}
    p["screenshotFileId"] = file_id
    p["screenshotUploadedAt"] = iso_utc_now()
    p["screenshotUploadedBy"] = auth.email
    portals_map[portal_key] = p
    checklist["portals"] = portals_map

    now = iso_utc_now()
    update_job_posting_row(
        db,
        requirement_id,
        {
            "screenshotUploadId": file_id,
            "checklistState": checklist,
            "updatedAt": now,
            "updatedBy": auth.email,
        },
    )

    append_audit(
        db,
        entityType="JOBPOST",
        entityId=requirement_id,
        action="JOBPOST_UPLOAD_SCREENSHOT",
        fromState=state.get("status") or "",
        toState=state.get("status") or "",
        stageTag="JOBPOST_UPLOAD_SCREENSHOT",
        remark=portal_key,
        actor=auth,
        at=now,
        meta={"portalKey": portal_key, "fileId": file_id, "mimeType": mime_type},
    )

    return {"fileId": file_id, "portalKey": portal_key}


def jobpost_mark_portal(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    portal_key = str((data or {}).get("portalKey") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not portal_key:
        raise ApiError("BAD_REQUEST", "Missing portalKey")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    state = get_job_posting_state(db, requirement_id)
    if not state:
        raise ApiError("NOT_FOUND", "JobPosting not initialized")
    if str(state.get("status") or "").upper() == "COMPLETE":
        raise ApiError("BAD_REQUEST", "JobPosting already complete")

    checklist = state.get("checklistState") or {"selectedPortals": [], "portals": {}}
    portals_map = checklist.get("portals") if isinstance(checklist, dict) else None
    p = portals_map.get(portal_key) if isinstance(portals_map, dict) else None
    if not isinstance(p, dict):
        raise ApiError("BAD_REQUEST", f"Portal not selected: {portal_key}")
    if not p.get("screenshotFileId"):
        raise ApiError("BAD_REQUEST", "Upload screenshot before marking posted")

    p["posted"] = True
    p["postedAt"] = iso_utc_now()
    p["postedBy"] = auth.email
    portals_map[portal_key] = p
    checklist["portals"] = portals_map

    now = iso_utc_now()
    update_job_posting_row(
        db,
        requirement_id,
        {"status": "IN_PROGRESS", "checklistState": checklist, "updatedAt": now, "updatedBy": auth.email},
    )

    append_audit(
        db,
        entityType="JOBPOST",
        entityId=requirement_id,
        action="JOBPOST_MARK_PORTAL",
        fromState=state.get("status") or "",
        toState="IN_PROGRESS",
        stageTag="JOBPOST_MARK_PORTAL",
        remark=portal_key,
        actor=auth,
        at=now,
        meta={"portalKey": portal_key},
    )

    return get_job_posting_state(db, requirement_id)


def jobpost_complete(data, auth: AuthContext | None, db, cfg):
    requirement_id = str((data or {}).get("requirementId") or "").strip()
    if not requirement_id:
        raise ApiError("BAD_REQUEST", "Missing requirementId")
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Login required")

    state = get_job_posting_state(db, requirement_id)
    if not state:
        raise ApiError("NOT_FOUND", "JobPosting not initialized")

    if str(state.get("status") or "").upper() == "COMPLETE":
        return state

    checklist = state.get("checklistState") or {"selectedPortals": [], "portals": {}}
    selected = checklist.get("selectedPortals") if isinstance(checklist, dict) else None
    if not isinstance(selected, list) or len(selected) == 0:
        raise ApiError("BAD_REQUEST", "Select portals first")

    portals_map = checklist.get("portals") if isinstance(checklist, dict) else None
    if not isinstance(portals_map, dict):
        portals_map = {}

    for psel in selected:
        k = (psel or {}).get("key") if isinstance(psel, dict) else None
        label = (psel or {}).get("label") if isinstance(psel, dict) else None
        k = str(k or "")
        p = portals_map.get(k) if k else None
        if not p or not isinstance(p, dict) or not p.get("posted"):
            raise ApiError("BAD_REQUEST", f"Not posted: {label or k}")
        if not p.get("screenshotFileId"):
            raise ApiError("BAD_REQUEST", f"Missing screenshot: {label or k}")

    now = iso_utc_now()
    update_job_posting_row(
        db,
        requirement_id,
        {"status": "COMPLETE", "completedAt": now, "completedBy": auth.email, "updatedAt": now, "updatedBy": auth.email},
    )

    append_audit(
        db,
        entityType="JOBPOST",
        entityId=requirement_id,
        action="JOBPOST_COMPLETE",
        fromState=state.get("status") or "",
        toState="COMPLETE",
        stageTag="JOBPOST_COMPLETE",
        remark="",
        actor=auth,
        at=now,
        meta={},
    )

    return get_job_posting_state(db, requirement_id)


def get_job_posting_state(db, requirement_id: str):
    jp = db.execute(select(JobPosting).where(JobPosting.requirementId == str(requirement_id))).scalar_one_or_none()
    if not jp:
        return None
    raw = str(jp.checklistStateJson or "").strip()
    try:
        checklist = json.loads(raw) if raw else {"selectedPortals": [], "portals": {}}
    except Exception:
        checklist = {"selectedPortals": [], "portals": {}}
    if not isinstance(checklist, dict):
        checklist = {"selectedPortals": [], "portals": {}}
    if not isinstance(checklist.get("selectedPortals"), list):
        checklist["selectedPortals"] = []
    if not isinstance(checklist.get("portals"), dict):
        checklist["portals"] = {}
    return {
        "requirementId": jp.requirementId,
        "status": jp.status,
        "checklistState": checklist,
        "screenshotUploadId": jp.screenshotUploadId or "",
        "completedAt": jp.completedAt or "",
        "completedBy": jp.completedBy or "",
        "updatedAt": jp.updatedAt or "",
        "updatedBy": jp.updatedBy or "",
    }


def update_job_posting_row(db, requirement_id: str, patch: dict):
    jp = db.execute(select(JobPosting).where(JobPosting.requirementId == str(requirement_id))).scalar_one_or_none()
    if not jp:
        raise ApiError("NOT_FOUND", "JobPosting row not found")

    if "status" in patch and patch["status"] is not None:
        jp.status = str(patch["status"])
    if "checklistState" in patch and patch["checklistState"] is not None:
        jp.checklistStateJson = json.dumps(patch["checklistState"])
    if "screenshotUploadId" in patch and patch["screenshotUploadId"] is not None:
        jp.screenshotUploadId = str(patch["screenshotUploadId"])
    if "completedAt" in patch and patch["completedAt"] is not None:
        jp.completedAt = patch["completedAt"] or ""
    if "completedBy" in patch and patch["completedBy"] is not None:
        jp.completedBy = str(patch["completedBy"] or "")
    if "updatedAt" in patch and patch["updatedAt"] is not None:
        jp.updatedAt = patch["updatedAt"] or ""
    if "updatedBy" in patch and patch["updatedBy"] is not None:
        jp.updatedBy = str(patch["updatedBy"] or "")


def ensure_job_posting_for_requirement(db, requirement_id: str, auth: AuthContext):
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


def assert_job_posting_complete(db, requirement_id: str):
    jp = db.execute(select(JobPosting).where(JobPosting.requirementId == str(requirement_id))).scalar_one_or_none()
    if not jp:
        raise ApiError("BAD_REQUEST", "JobPosting not initialized")
    if str(jp.status or "").upper() != "COMPLETE":
        raise ApiError("BAD_REQUEST", "JobPosting not complete")


def sanitize_portal_key(label: str) -> str:
    s = str(label or "").upper()
    import re

    s = re.sub(r"[^A-Z0-9]+", "_", s)
    s = re.sub(r"^_+|_+$", "", s)
    return s or "PORTAL"


def normalize_portals(portals: list) -> list[dict]:
    out = []
    used = set()
    for raw in portals:
        name = str(raw or "").strip()
        if not name:
            continue
        upper = name.upper()
        if upper == "NAUKRI":
            label = "Naukri"
        elif upper == "APNA":
            label = "Apna"
        elif upper == "INDEED":
            label = "Indeed"
        elif upper == "WORKINDIA":
            label = "WorkIndia"
        else:
            label = name

        if upper in {"NAUKRI", "APNA", "INDEED", "WORKINDIA"}:
            base_key = upper
        else:
            base_key = sanitize_portal_key(label)
            if base_key == "CUSTOM":
                base_key = "CUSTOM_PORTAL"
            base_key = "CUSTOM_" + base_key

        key = base_key
        n = 2
        while key in used:
            key = f"{base_key}_{n}"
            n += 1
        used.add(key)
        out.append({"key": key, "label": label})
    return out


def merge_portals_into_checklist_state(existing, selected_portals: list[dict]) -> dict:
    state = existing if isinstance(existing, dict) else {}
    selected_prev = state.get("selectedPortals") if isinstance(state.get("selectedPortals"), list) else []
    portals_prev = state.get("portals") if isinstance(state.get("portals"), dict) else {}

    next_state = {"selectedPortals": [], "portals": {}}
    for p in selected_portals:
        next_state["selectedPortals"].append({"key": p.get("key"), "label": p.get("label")})
        prev = portals_prev.get(p.get("key")) if isinstance(portals_prev, dict) else {}
        prev = prev if isinstance(prev, dict) else {}
        next_state["portals"][p.get("key")] = {
            "posted": bool(prev.get("posted")),
            "postedAt": prev.get("postedAt") or "",
            "postedBy": prev.get("postedBy") or "",
            "screenshotFileId": prev.get("screenshotFileId") or "",
            "screenshotUploadedAt": prev.get("screenshotUploadedAt") or "",
            "screenshotUploadedBy": prev.get("screenshotUploadedBy") or "",
        }
    return next_state

