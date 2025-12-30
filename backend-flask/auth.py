from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from sqlalchemy import select

from models import Permission, Role, Session as DbSession
from utils import ApiError, AuthContext, normalize_role, parse_roles_csv, sha256_hex, iso_utc_now, new_uuid


PUBLIC_ACTIONS = {
    "LOGIN_EXCHANGE",
    "EMPLOYEE_LOGIN",
    "TEST_TOKEN_VALIDATE",
    "TEST_QUESTIONS_GET",
    "TEST_SUBMIT_PUBLIC",
    "TEST_RESULT_GET",
}


STATIC_RBAC_PERMISSIONS: dict[str, list[str]] = {
    "LOGIN_EXCHANGE": ["PUBLIC"],
    "EMPLOYEE_LOGIN": ["PUBLIC"],
    "SESSION_VALIDATE": ["ADMIN", "EA", "HR", "OWNER"],
    "GET_ME": ["ADMIN", "EA", "HR", "OWNER"],
    "MY_PERMISSIONS_GET": ["ADMIN", "EA", "HR", "OWNER"],
    "USERS_LIST": ["ADMIN"],
    "USERS_UPSERT": ["ADMIN"],
    "ROLES_LIST": ["ADMIN"],
    "ROLES_UPSERT": ["ADMIN"],
    "PERMISSIONS_LIST": ["ADMIN"],
    "PERMISSIONS_UPSERT": ["ADMIN"],
    "TEMPLATE_LIST": ["ADMIN", "EA"],
    "TEMPLATE_UPSERT": ["ADMIN"],
    "SETTINGS_GET": ["ADMIN"],
    "SETTINGS_UPSERT": ["ADMIN"],
    "COPY_TEMPLATE_DATA": ["ADMIN", "HR"],
    "LOGS_QUERY": ["ADMIN"],
    "REQUIREMENT_CREATE": ["ADMIN", "EA"],
    "REQUIREMENT_UPDATE": ["ADMIN", "EA"],
    "REQUIREMENT_SUBMIT": ["ADMIN", "EA"],
    "REQUIREMENT_RESUBMIT": ["ADMIN", "EA"],
    "REQUIREMENT_GET": ["ADMIN", "EA", "HR"],
    "REQUIREMENT_LIST_BY_ROLE": ["ADMIN", "EA"],
    "HR_REQUIREMENTS_LIST": ["ADMIN", "HR"],
    "REQUIREMENT_APPROVE": ["ADMIN", "HR"],
    "REQUIREMENT_CLARIFICATION": ["ADMIN", "HR"],
    "JOBPOST_INIT": ["ADMIN", "HR"],
    "JOBPOST_SET_PORTALS": ["ADMIN", "HR"],
    "JOBPOST_UPLOAD_SCREENSHOT": ["ADMIN", "HR"],
    "JOBPOST_MARK_PORTAL": ["ADMIN", "HR"],
    "JOBPOST_COMPLETE": ["ADMIN", "HR"],
    "FILE_UPLOAD_CV": ["ADMIN", "HR"],
    "CANDIDATE_ADD": ["ADMIN", "HR"],
    "CANDIDATE_BULK_ADD": ["ADMIN", "HR"],
    "SHORTLIST_DECIDE": ["ADMIN", "HR"],
    "SHORTLIST_HOLD_REVERT": ["ADMIN", "HR"],
    "OWNER_CANDIDATES_LIST": ["ADMIN", "OWNER"],
    "OWNER_DECIDE": ["ADMIN", "OWNER"],
    "HR_WALKIN_SCHEDULE": ["ADMIN", "HR"],
    "WALKIN_SCHEDULE": ["ADMIN", "HR"],
    "PRECALL_LIST": ["ADMIN", "HR"],
    "PRECALL_UPDATE": ["ADMIN", "HR"],
    "AUTO_REJECT_NOTPICK": ["ADMIN"],
    "PREINTERVIEW_STATUS": ["ADMIN", "HR"],
    "PREINTERVIEW_MARKS_SAVE": ["ADMIN", "HR"],
    "TEST_LINK_CREATE": ["ADMIN", "HR"],
    "TEST_TOKEN_VALIDATE": ["PUBLIC"],
    "TEST_QUESTIONS_GET": ["PUBLIC"],
    "TEST_SUBMIT_PUBLIC": ["PUBLIC"],
    "TEST_RESULT_GET": ["PUBLIC"],
    "INPERSON_PIPELINE_LIST": ["ADMIN", "HR"],
    "INPERSON_MARKS_SAVE": ["ADMIN", "HR"],
    "TECH_SELECT": ["ADMIN", "HR"],
    "AUTO_REJECT_INPERSON_LOW": ["ADMIN"],
    "TECH_PENDING_LIST": ["ADMIN", "EA", "HR"],
    "EA_TECH_MARKS_SUBMIT": ["ADMIN", "EA"],
    "ADMIN_EXCEL_MARKS_SUBMIT": ["ADMIN"],
    "PASSFAIL_EVALUATE": ["ADMIN", "EA", "HR"],
    "TEST_FAIL_DECIDE": ["ADMIN", "EA", "HR"],
    "TRAINING_MASTER_LIST": ["ADMIN", "HR"],
    "TRAINING_MASTER_UPSERT": ["ADMIN"],
    "TRAINING_ASSIGN": ["ADMIN", "HR"],
    "TRAINING_LIST": ["ADMIN", "EA", "HR", "OWNER", "EMPLOYEE"],
    "TRAINING_STATUS_UPDATE": ["ADMIN", "HR", "EMPLOYEE"],
    "TRAINING_SUMMARY": ["ADMIN", "EA", "HR", "OWNER"],
    "TRAINING_DASHBOARD": ["ADMIN", "HR"],
    "FINAL_INTERVIEW_LIST": ["ADMIN", "HR"],
    "FINAL_SEND_OWNER": ["ADMIN", "HR"],
    "OWNER_FINAL_DECIDE": ["ADMIN", "OWNER"],
    "HR_FINAL_HOLD_LIST": ["ADMIN", "HR"],
    "HR_HOLD_SCHEDULE": ["ADMIN", "HR"],
    "AUTO_REJECT_FINAL_NOSHOW": ["ADMIN"],
    "JOINING_LIST": ["ADMIN", "HR"],
    "JOINING_SET_DATE": ["ADMIN", "HR"],
    "DOCS_UPLOAD": ["ADMIN", "HR"],
    "DOCS_COMPLETE": ["ADMIN", "HR"],
    "MARK_JOIN": ["ADMIN", "HR"],
    "PROBATION_LIST": ["ADMIN", "HR"],
    "PROBATION_SET": ["ADMIN", "HR"],
    "PROBATION_DECIDE": ["ADMIN", "HR"],
    "ROLE_CHANGE": ["ADMIN", "EA"],
    "EMPLOYEE_CREATE_FROM_CANDIDATE": ["ADMIN", "HR"],
    "EMPLOYEE_GET": ["ADMIN", "EA", "HR", "OWNER"],
    "REQUIREMENT_AUTO_CLOSE": ["ADMIN"],
    "REJECTION_LOG_LIST": ["ADMIN", "EA", "HR"],
    "REJECT_REVERT": ["ADMIN"],
    "HOLD_REVERT": ["ADMIN", "OWNER", "EA"],
    "HOLD_EXPIRY_CRON": ["ADMIN"],
}


def is_public_action(action: str) -> bool:
    return str(action or "").upper() in PUBLIC_ACTIONS


def verify_google_id_token(id_token: str, google_client_id: str, allow_test_tokens: bool = False) -> dict[str, Any]:
    if not google_client_id:
        raise ApiError("INTERNAL", "Missing GOOGLE_CLIENT_ID")
    if not id_token or not isinstance(id_token, str):
        raise ApiError("BAD_REQUEST", "Missing idToken")

    if allow_test_tokens and id_token.startswith("TEST:"):
        email = id_token.split(":", 1)[1].strip().lower()
        if not email:
            raise ApiError("AUTH_INVALID", "Invalid test token")
        return {"email": email, "fullName": "Test User", "picture": "", "sub": "TEST", "exp": 0}

    try:
        req = google_requests.Request()
        payload = google_id_token.verify_oauth2_token(id_token, req, audience=google_client_id)
    except Exception:
        raise ApiError("AUTH_INVALID", "Invalid Google ID token")

    aud = payload.get("aud")
    if aud != google_client_id:
        raise ApiError("AUTH_INVALID", "Google token audience mismatch")

    if str(payload.get("email_verified", "")).lower() != "true":
        raise ApiError("AUTH_INVALID", "Google email not verified")

    return {
        "email": str(payload.get("email", "")).lower(),
        "fullName": payload.get("name", "") or "",
        "picture": payload.get("picture", "") or "",
        "sub": payload.get("sub", "") or "",
        "exp": payload.get("exp", 0) or 0,
    }


def _parse_iso_utc_maybe(value: str) -> Optional[datetime]:
    s = str(value or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None


def issue_session_token(
    db,
    *,
    user_id: str,
    email: str,
    role: str,
    session_ttl_minutes: int,
) -> dict[str, str]:
    token = "ST-" + uuid_hex_32() + uuid_hex_32()
    token_hash = sha256_hex(token)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=session_ttl_minutes)

    issued_at = iso_utc_now()
    expires_at = expires.replace(microsecond=(expires.microsecond // 1000) * 1000).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )

    ses = DbSession(
        sessionId="SES-" + new_uuid(),
        tokenHash=token_hash,
        tokenPrefix=token[:12],
        userId=str(user_id or ""),
        email=str(email or ""),
        role=str(normalize_role(role) or ""),
        issuedAt=issued_at,
        expiresAt=expires_at,
        lastSeenAt=issued_at,
        revokedAt="",
        revokedBy="",
    )
    db.add(ses)
    return {"sessionToken": token, "expiresAt": expires_at}


def uuid_hex_32() -> str:
    return new_uuid().replace("-", "")


def validate_session_token(db, token: Any) -> AuthContext:
    if not token or not isinstance(token, str):
        return AuthContext(valid=False, userId="", email="", role="", expiresAt="")

    token_hash = sha256_hex(token)
    ses = db.execute(select(DbSession).where(DbSession.tokenHash == token_hash)).scalar_one_or_none()
    if not ses:
        return AuthContext(valid=False, userId="", email="", role="", expiresAt="")

    if getattr(ses, "revokedAt", ""):
        return AuthContext(valid=False, userId="", email="", role="", expiresAt="")

    expires_at = getattr(ses, "expiresAt", "") or ""
    exp_dt = _parse_iso_utc_maybe(expires_at)
    if exp_dt and exp_dt < datetime.now(timezone.utc):
        return AuthContext(valid=False, userId="", email="", role="", expiresAt="")

    ses.lastSeenAt = iso_utc_now()

    return AuthContext(
        valid=True,
        userId=str(getattr(ses, "userId", "") or ""),
        email=str(getattr(ses, "email", "") or ""),
        role=str(normalize_role(getattr(ses, "role", "")) or ""),
        expiresAt=expires_at,
    )


def get_permission_rule(db, perm_type: str, perm_key: str) -> Optional[dict[str, Any]]:
    perm_type_u = str(perm_type or "").upper().strip()
    perm_key_u = str(perm_key or "").upper().strip()
    if not perm_type_u or not perm_key_u:
        return None
    row = (
        db.execute(
            select(Permission).where(Permission.permType == perm_type_u).where(Permission.permKey == perm_key_u)
        )
        .scalars()
        .first()
    )
    if not row:
        return None
    return {
        "enabled": bool(row.enabled),
        "roles": parse_roles_csv(row.rolesCsv or ""),
        "rolesCsv": row.rolesCsv or "",
    }


def _roles_index(db) -> dict[str, dict[str, Any]]:
    rows = db.execute(select(Role)).scalars().all()
    out: dict[str, dict[str, Any]] = {}
    if not rows:
        for rc in ["ADMIN", "EA", "HR", "OWNER", "EMPLOYEE"]:
            out[rc] = {"roleCode": rc, "roleName": rc, "status": "ACTIVE"}
        return out
    for r in rows:
        code = normalize_role(r.roleCode)
        if not code:
            continue
        out[code] = {
            "roleCode": code,
            "roleName": str(r.roleName or code),
            "status": str(r.status or "ACTIVE").upper(),
        }
    return out


def is_role_active(db, role: str) -> bool:
    r = normalize_role(role)
    if not r:
        return False
    idx = _roles_index(db)
    it = idx.get(r)
    if not it:
        return False
    return str(it.get("status", "")).upper() == "ACTIVE"


def assert_permission(db, role: str, action: str) -> None:
    role_u = normalize_role(role) or ""
    action_u = str(action or "").upper().strip()

    if is_public_action(action_u):
        return

    allowed_static = STATIC_RBAC_PERMISSIONS.get(action_u)
    rule = get_permission_rule(db, "ACTION", action_u)
    has_dyn = bool(rule and rule.get("enabled") is True)

    if not allowed_static and not has_dyn:
        raise ApiError("BAD_REQUEST", f"Unknown action: {action_u}")

    if not role_u:
        raise ApiError("AUTH_INVALID", "Login required")
    if not is_role_active(db, role_u):
        raise ApiError("FORBIDDEN", f"Inactive or unknown role: {role_u}")

    if not has_dyn and action_u in {"SESSION_VALIDATE", "GET_ME", "MY_PERMISSIONS_GET"}:
        return

    ok = False
    if has_dyn:
        roles = rule.get("roles") or []
        if "PUBLIC" in roles:
            ok = True
        else:
            ok = role_u in roles
    else:
        allowed = allowed_static or []
        ok = role_u in allowed

    if not ok:
        raise ApiError("FORBIDDEN", f"Not allowed for role: {role_u}")


def permissions_for_role(db, role: str) -> dict[str, Any]:
    role_u = normalize_role(role)
    if not role_u:
        raise ApiError("AUTH_INVALID", "Login required")

    ui_keys: list[str] = []
    action_keys: list[str] = []

    rows = db.execute(select(Permission).where(Permission.enabled == True)).scalars().all()  # noqa: E712
    for row in rows:
        perm_type = str(row.permType or "").upper().strip()
        perm_key = str(row.permKey or "").upper().strip()
        if not perm_type or not perm_key:
            continue
        roles = parse_roles_csv(row.rolesCsv or "")
        if role_u not in roles and "PUBLIC" not in roles:
            continue
        if perm_type == "UI":
            ui_keys.append(perm_key)
        elif perm_type == "ACTION":
            action_keys.append(perm_key)

    ui_keys.sort()
    action_keys.sort()
    portal_keys = [k for k in ui_keys if k.startswith("PORTAL_")]
    return {"role": role_u, "uiKeys": ui_keys, "portalKeys": portal_keys, "actionKeys": action_keys}


def serialize_auth(auth: AuthContext) -> dict[str, Any]:
    return {"valid": bool(auth.valid), "expiresAt": auth.expiresAt, "me": {"email": auth.email, "role": role_or_public(auth)}}


def role_or_public(auth: Optional[AuthContext]) -> str:
    if not auth or not auth.valid:
        return "PUBLIC"
    return normalize_role(auth.role) or "PUBLIC"

