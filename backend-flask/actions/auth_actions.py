from __future__ import annotations

from sqlalchemy import func, select

from actions.helpers import append_audit
from auth import issue_session_token, verify_google_id_token
from models import Employee, User
from utils import ApiError, AuthContext, iso_utc_now, normalize_role


def _find_user_by_email(db, email: str):
    email_lc = str(email or "").lower().strip()
    if not email_lc:
        return None
    return (
        db.execute(select(User).where(func.lower(User.email) == email_lc))
        .scalars()
        .first()
    )


def _update_user_last_login(db, email: str):
    u = _find_user_by_email(db, email)
    if not u:
        return
    u.lastLoginAt = iso_utc_now()


def _find_employee_by_employee_id(db, employee_id: str):
    emp_id = str(employee_id or "").strip()
    if not emp_id:
        return None
    return db.execute(select(Employee).where(Employee.employeeId == emp_id)).scalar_one_or_none()


def login_exchange(data, auth: AuthContext | None, db, cfg):
    id_token = (data or {}).get("idToken")
    google_user = verify_google_id_token(
        id_token,
        google_client_id=cfg.GOOGLE_CLIENT_ID,
        allow_test_tokens=bool(cfg.AUTH_ALLOW_TEST_TOKENS),
    )

    user = _find_user_by_email(db, google_user.get("email"))
    if not user:
        raise ApiError("AUTH_INVALID", "User not found in Users")

    if str(user.status or "").upper() != "ACTIVE":
        raise ApiError("AUTH_INVALID", "User is disabled")

    _update_user_last_login(db, user.email)
    ses = issue_session_token(
        db,
        user_id=user.userId,
        email=user.email,
        role=user.role,
        session_ttl_minutes=cfg.SESSION_TTL_MINUTES,
    )

    append_audit(
        db,
        entityType="AUTH",
        entityId=str(user.userId),
        action="LOGIN_EXCHANGE",
        stageTag="AUTH_LOGIN",
        remark="",
        actor=AuthContext(valid=True, userId=user.userId, email=user.email, role=normalize_role(user.role) or "", expiresAt=ses["expiresAt"]),
        meta={"email": user.email},
    )

    return {
        "sessionToken": ses["sessionToken"],
        "expiresAt": ses["expiresAt"],
        "me": {
            "userId": user.userId,
            "email": user.email,
            "fullName": user.fullName or google_user.get("fullName") or "",
            "role": normalize_role(user.role),
        },
    }


def employee_login(data, auth: AuthContext | None, db, cfg):
    employee_id = str((data or {}).get("employeeId") or "").strip()
    if not employee_id:
        raise ApiError("BAD_REQUEST", "Missing employeeId")

    emp = _find_employee_by_employee_id(db, employee_id)
    if not emp:
        raise ApiError("AUTH_INVALID", "Invalid employeeId")
    if not str(emp.candidateId or "").strip():
        raise ApiError("AUTH_INVALID", "Employee not linked to candidate")

    user_id = emp.employeeId
    ses = issue_session_token(
        db,
        user_id=user_id,
        email="",
        role="EMPLOYEE",
        session_ttl_minutes=cfg.SESSION_TTL_MINUTES,
    )

    try:
        append_audit(
            db,
            entityType="AUTH",
            entityId=str(user_id),
            action="EMPLOYEE_LOGIN",
            stageTag="AUTH_LOGIN",
            remark="",
            actor=AuthContext(valid=True, userId=user_id, email="", role="EMPLOYEE", expiresAt=ses["expiresAt"]),
            meta={"employeeId": emp.employeeId, "candidateId": emp.candidateId},
        )
    except Exception:
        pass

    return {
        "sessionToken": ses["sessionToken"],
        "expiresAt": ses["expiresAt"],
        "me": {
            "userId": emp.employeeId,
            "email": "",
            "fullName": emp.employeeName or emp.employeeId,
            "role": "EMPLOYEE",
            "employeeId": emp.employeeId,
            "candidateId": emp.candidateId,
            "jobRole": emp.jobRole or "",
            "jobTitle": emp.jobTitle or "",
        },
    }


def session_validate(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Invalid or expired session")
    return {
        "valid": True,
        "expiresAt": auth.expiresAt,
        "me": {"email": auth.email, "role": normalize_role(auth.role)},
    }


def get_me(data, auth: AuthContext | None, db, cfg):
    if not auth or not auth.valid:
        raise ApiError("AUTH_INVALID", "Invalid or expired session")

    if normalize_role(auth.role) == "EMPLOYEE":
        emp_id = str(auth.userId or "").strip()
        emp = _find_employee_by_employee_id(db, emp_id)
        if not emp:
            raise ApiError("AUTH_INVALID", "Employee missing")
        return {
            "me": {
                "userId": emp.employeeId,
                "email": "",
                "fullName": emp.employeeName or emp.employeeId,
                "role": "EMPLOYEE",
                "employeeId": emp.employeeId,
                "candidateId": emp.candidateId or "",
                "jobRole": emp.jobRole or "",
                "jobTitle": emp.jobTitle or "",
            }
        }

    user = _find_user_by_email(db, auth.email)
    if not user:
        raise ApiError("AUTH_INVALID", "User missing")
    if str(user.status or "").upper() != "ACTIVE":
        raise ApiError("AUTH_INVALID", "User is disabled")

    return {
        "me": {
            "userId": user.userId,
            "email": user.email,
            "fullName": user.fullName or "",
            "role": normalize_role(user.role),
        }
    }

