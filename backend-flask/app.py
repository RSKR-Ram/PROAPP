from __future__ import annotations

import glob
import json
import logging
import mimetypes
import os
import re
from typing import Any

from dotenv import load_dotenv
from flask import Flask, g, request, send_file
from flask_cors import CORS

from actions import dispatch
from auth import assert_permission, is_public_action, role_or_public, validate_session_token
from config import Config
from db import SessionLocal, init_engine
from models import AuditLog, Permission, Role
from utils import ApiError, SimpleRateLimiter, err, iso_utc_now, now_monotonic, ok, parse_json_body, redact_for_audit


def _configure_logging(level: str):
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _seed_roles_and_permissions(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    # Roles seed
    existing_roles = {r.roleCode.upper() for r in db.query(Role).all()}  # type: ignore[attr-defined]
    needed = ["ADMIN", "EA", "HR", "OWNER", "EMPLOYEE"]
    for rc in needed:
        if rc in existing_roles:
            continue
        db.add(
            Role(
                roleCode=rc,
                roleName=rc,
                status="ACTIVE",
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )

    # Permissions seed (only if empty)
    existing_perm_count = db.query(Permission).count()  # type: ignore[attr-defined]
    if existing_perm_count:
        return

    ui_rows = []
    ui_rows.append(("UI", "PORTAL_ADMIN", "ADMIN", True))
    ui_rows.append(("UI", "PORTAL_REQUIREMENTS", "EA,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_REVIEW", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_PRECALL", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_PREINTERVIEW", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_INPERSON", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_FINAL", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_FINAL_HOLD", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_JOINING", "HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_HR_PROBATION", "HR,EA,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_OWNER", "OWNER,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_EA_TECH", "EA,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_REJECTION_LOG", "EA,HR,ADMIN", True))
    ui_rows.append(("UI", "PORTAL_EMPLOYEE_PROFILE", "EA,HR,OWNER,ADMIN", True))
    ui_rows.append(("UI", "BTN_SHORTLIST_OWNER_SEND", "HR,ADMIN", True))
    ui_rows.append(("UI", "BTN_OWNER_APPROVE_WALKIN", "OWNER,ADMIN", True))
    ui_rows.append(("UI", "SECTION_EXCEL_MARKS", "ADMIN", True))

    for perm_type, perm_key, roles_csv, enabled in ui_rows:
        db.add(
            Permission(
                permType=perm_type,
                permKey=perm_key,
                rolesCsv=roles_csv,
                enabled=bool(enabled),
                updatedAt=now,
                updatedBy=actor,
            )
        )

    # ACTION permissions seed from static mapping for easier future edits.
    from auth import STATIC_RBAC_PERMISSIONS

    for action, roles in STATIC_RBAC_PERMISSIONS.items():
        key = action.upper()
        if key in {"SESSION_VALIDATE", "GET_ME", "MY_PERMISSIONS_GET"}:
            continue
        db.add(
            Permission(
                permType="ACTION",
                permKey=key,
                rolesCsv=",".join(roles),
                enabled=True,
                updatedAt=now,
                updatedBy=actor,
            )
        )


def create_app() -> Flask:
    load_dotenv()
    cfg = Config()
    _configure_logging(cfg.LOG_LEVEL)

    engine = init_engine(cfg.DATABASE_URL)
    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    from models import Base  # imported after engine init

    Base.metadata.create_all(bind=engine)

    app = Flask(__name__)
    app.config["CFG"] = cfg

    CORS(app, origins=cfg.ALLOWED_ORIGINS, supports_credentials=False)

    limiter = SimpleRateLimiter()

    # Seed roles/permissions at startup (idempotent).
    db0 = SessionLocal()
    try:
        _seed_roles_and_permissions(db0)
        db0.commit()
    finally:
        db0.close()

    @app.before_request
    def _before():
        g.request_id = os.urandom(8).hex()
        g.start_ts = now_monotonic()

    @app.get("/health")
    def health():
        return ok({"status": "ok"})[0]

    @app.get("/")
    def index():
        return ok(
            {
                "status": "ok",
                "message": "HRMS backend is running. Use /health for a quick check and POST /api for actions.",
                "endpoints": {"health": "/health", "api": "/api"},
                "note": "In a browser, open http://127.0.0.1:5000/health (do not type 'GET /health' in the URL).",
            }
        )[0]

    @app.get("/files/<file_id>")
    def files_get(file_id: str):
        cfg2: Config = app.config["CFG"]
        fid = str(file_id or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", fid):
            return err("BAD_REQUEST", "Invalid file id", http_status=400)[0], 400

        token_q = str(request.args.get("token") or "").strip()
        token_h = str(request.headers.get("Authorization") or "").strip()
        token = token_q
        if token_h.lower().startswith("bearer "):
            token = token_h[7:].strip()

        if not token:
            return err("AUTH_INVALID", "Missing token", http_status=401)[0], 401

        db = SessionLocal()
        try:
            auth_ctx = validate_session_token(db, token)
            if not auth_ctx.valid:
                return err("AUTH_INVALID", "Invalid or expired session", http_status=401)[0], 401

            role = role_or_public(auth_ctx)
            if role == "PUBLIC":
                return err("AUTH_INVALID", "Login required", http_status=401)[0], 401

            # EMPLOYEE role can only access its own candidate/employee files.
            if role == "EMPLOYEE":
                try:
                    from sqlalchemy import select

                    from models import Candidate, Employee

                    emp = db.execute(select(Employee).where(Employee.employeeId == str(auth_ctx.userId or ""))).scalar_one_or_none()
                    if not emp:
                        return err("FORBIDDEN", "Employee not found", http_status=403)[0], 403

                    allowed = set()
                    if str(emp.cvFileId or "").strip():
                        allowed.add(str(emp.cvFileId).strip())

                    cand_id = str(emp.candidateId or "").strip()
                    if cand_id:
                        cand = db.execute(select(Candidate).where(Candidate.candidateId == cand_id)).scalar_one_or_none()
                        if cand and str(cand.cvFileId or "").strip():
                            allowed.add(str(cand.cvFileId).strip())
                        try:
                            docs = json.loads(str(getattr(cand, "docsJson", "") or "[]")) if cand else []
                            if isinstance(docs, list):
                                for d in docs:
                                    if isinstance(d, dict) and str(d.get("fileId") or "").strip():
                                        allowed.add(str(d.get("fileId")).strip())
                        except Exception:
                            pass

                    if fid not in allowed:
                        return err("FORBIDDEN", "File not accessible", http_status=403)[0], 403
                except Exception:
                    return err("FORBIDDEN", "File not accessible", http_status=403)[0], 403

            pattern = os.path.join(cfg2.UPLOAD_DIR, f"{fid}_*")
            matches = sorted(glob.glob(pattern))
            if not matches:
                return err("NOT_FOUND", "File not found", http_status=404)[0], 404

            path = matches[0]
            name = os.path.basename(path)
            download_name = name[len(fid) + 1 :] if name.startswith(fid + "_") else name
            mime, _enc = mimetypes.guess_type(download_name)
            mime = mime or "application/octet-stream"

            resp = send_file(path, mimetype=mime, as_attachment=False, download_name=download_name)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp
        finally:
            try:
                db.close()
            except Exception:
                pass

    @app.errorhandler(404)
    def not_found(_e):
        path = request.path
        return (
            err(
                "NOT_FOUND",
                f"Unknown endpoint: {path}. Use GET /health in browser, and POST /api for actions (don’t type 'GET'/'POST' in the URL).",
                http_status=404,
            )
        )

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return err("BAD_REQUEST", "Method not allowed. Use POST /api for actions.", http_status=405)

    @app.post("/api")
    def api_route():
        cfg2: Config = app.config["CFG"]
        raw = request.get_data(as_text=True)
        db = None
        auth_ctx = None
        action_u = ""
        token = None
        data: Any = {}

        try:
            body = parse_json_body(raw)
            action_u = str(body.get("action") or "").upper().strip()
            token = body.get("token")
            data = body.get("data") or {}

            if not action_u:
                raise ApiError("BAD_REQUEST", "Missing action")

            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            login_actions = {"LOGIN_EXCHANGE", "EMPLOYEE_LOGIN"}
            if action_u in login_actions:
                limiter.check(f"{ip}:LOGIN", cfg2.RATE_LIMIT_LOGIN)
            else:
                # Use a generous global limit + a per-action limit to avoid blocking normal SPA usage.
                limiter.check(f"{ip}:GLOBAL", cfg2.RATE_LIMIT_GLOBAL)
                limiter.check(f"{ip}:API:{action_u}", cfg2.RATE_LIMIT_DEFAULT)

            db = SessionLocal()

            if action_u != "LOGIN_EXCHANGE" and not is_public_action(action_u):
                auth_ctx = validate_session_token(db, token)
                if not auth_ctx.valid:
                    raise ApiError("AUTH_INVALID", "Invalid or expired session")
            else:
                if token:
                    maybe = validate_session_token(db, token)
                    auth_ctx = maybe if maybe.valid else None

            role = role_or_public(auth_ctx)
            assert_permission(db, role, action_u)

            out = dispatch(action_u, data, auth_ctx, db, cfg2)

            # Audit API_CALL
            try:
                db.add(
                    AuditLog(
                        logId=f"LOG-{os.urandom(16).hex()}",
                        entityType="API",
                        entityId=str(auth_ctx.userId or auth_ctx.email or "") if auth_ctx else "PUBLIC",
                        action=action_u,
                        fromState="",
                        toState="",
                        stageTag="API_CALL",
                        remark="",
                        actorUserId=str(auth_ctx.userId) if auth_ctx else "PUBLIC",
                        actorRole=str(auth_ctx.role) if auth_ctx else "PUBLIC",
                        at=iso_utc_now(),
                        metaJson=json.dumps({"data": redact_for_audit(data)}),
                    )
                )
            except Exception:
                pass

            db.commit()

            latency_ms = int((now_monotonic() - g.start_ts) * 1000)
            logging.getLogger("api").info(
                "request_id=%s action=%s user=%s role=%s latency_ms=%s",
                g.request_id,
                action_u,
                (auth_ctx.userId if auth_ctx else "PUBLIC"),
                (auth_ctx.role if auth_ctx else "PUBLIC"),
                latency_ms,
            )

            return ok(out)[0]
        except ApiError as e:
            if db is not None:
                db.rollback()
            _write_error_audit(cfg2, action_u, auth_ctx, data, e)
            return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
        except Exception:
            if db is not None:
                db.rollback()
            api_err = ApiError("INTERNAL", "Unexpected error")
            _write_error_audit(cfg2, action_u, auth_ctx, data, api_err)
            logging.getLogger("api").exception("request_id=%s action=%s", g.request_id, action_u)
            return err(api_err.code, api_err.message)[0]
        finally:
            if db is not None:
                db.close()

    return app


def _write_error_audit(cfg: Config, action: str, auth_ctx, data: Any, err_obj: ApiError):
    if SessionLocal is None:
        return
    try:
        db2 = SessionLocal()
        db2.add(
            AuditLog(
                logId=f"LOG-{os.urandom(16).hex()}",
                entityType="API",
                entityId=str(auth_ctx.userId or auth_ctx.email or "") if auth_ctx else "PUBLIC",
                action=str(action or "").upper() or "UNKNOWN",
                fromState="",
                toState="",
                stageTag="API_ERROR",
                remark=f"{err_obj.code}: {err_obj.message}",
                actorUserId=str(auth_ctx.userId) if auth_ctx else "PUBLIC",
                actorRole=str(auth_ctx.role) if auth_ctx else "PUBLIC",
                at=iso_utc_now(),
                metaJson=json.dumps(
                    {
                        "data": redact_for_audit(data or {}),
                        "error": {"code": err_obj.code, "message": err_obj.message},
                    }
                ),
            )
        )
        db2.commit()
    except Exception:
        pass
    finally:
        try:
            db2.close()
        except Exception:
            pass


if __name__ == "__main__":
    app = create_app()
    cfg = app.config["CFG"]

    os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    app.run(host=cfg.HOST, port=cfg.PORT)
