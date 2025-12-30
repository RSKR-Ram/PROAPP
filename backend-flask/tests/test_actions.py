from __future__ import annotations

from typing import Any

from db import SessionLocal
from models import JobTemplate, User
from utils import iso_utc_now


def _seed_admin_user(email: str = "admin@example.com") -> None:
    db = SessionLocal()
    try:
        now = iso_utc_now()
        db.add(
            User(
                userId="U-ADMIN",
                email=email,
                fullName="Admin",
                role="ADMIN",
                status="ACTIVE",
                lastLoginAt="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()
    finally:
        db.close()


def _seed_job_template(template_id: str = "TPL-1") -> None:
    db = SessionLocal()
    try:
        now = iso_utc_now()
        db.add(
            JobTemplate(
                templateId=template_id,
                jobRole="ENGINEER",
                jobTitle="Software Engineer",
                jd="",
                responsibilities="",
                skills="",
                shift="",
                payScale="",
                perks="",
                notes="",
                status="ACTIVE",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()
    finally:
        db.close()


def _api(client, *, action: str, token: str | None = None, data: dict[str, Any] | None = None):
    payload = {"action": action, "token": token or "", "data": data or {}}
    return client.post("/api", json=payload)


def _login_admin(client) -> str:
    _seed_admin_user()
    resp = _api(client, action="LOGIN_EXCHANGE", data={"idToken": "TEST:admin@example.com"})
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["ok"] is True
    token = body["data"]["sessionToken"]
    assert isinstance(token, str) and token
    return token


def _create_requirement(client, token: str, template_id: str = "TPL-1") -> str:
    _seed_job_template(template_id)
    resp = _api(
        client,
        action="REQUIREMENT_CREATE",
        token=token,
        data={
            "templateId": template_id,
            "requiredCount": 1,
            "raisedFor": "IT",
            "concernedPerson": "Alice",
        },
    )
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["ok"] is True
    rid = body["data"]["requirementId"]
    assert isinstance(rid, str) and rid
    return rid


def test_login_exchange_action(app_client):
    _app, client = app_client
    _seed_admin_user()

    resp = _api(client, action="LOGIN_EXCHANGE", data={"idToken": "TEST:admin@example.com"})
    body = resp.get_json()

    assert resp.status_code == 200
    assert body["ok"] is True
    assert isinstance(body["data"]["sessionToken"], str) and body["data"]["sessionToken"]


def test_users_list_action(app_client):
    _app, client = app_client
    token = _login_admin(client)

    resp = _api(client, action="USERS_LIST", token=token, data={"page": 1, "pageSize": 50})
    body = resp.get_json()

    assert resp.status_code == 200
    assert body["ok"] is True
    assert body["data"]["total"] >= 1
    assert any(u.get("email") == "admin@example.com" for u in body["data"]["items"])


def test_requirement_create_action(app_client):
    _app, client = app_client
    token = _login_admin(client)

    rid = _create_requirement(client, token)
    assert rid.startswith("REQ-NTW-")


def test_requirement_update_action(app_client):
    _app, client = app_client
    token = _login_admin(client)
    rid = _create_requirement(client, token)

    resp = _api(
        client,
        action="REQUIREMENT_UPDATE",
        token=token,
        data={"requirementId": rid, "requiredCount": 2, "jobTitle": "Software Engineer II"},
    )
    body = resp.get_json()

    assert resp.status_code == 200
    assert body["ok"] is True
    assert body["data"]["requirementId"] == rid


def test_requirement_submit_transition_action(app_client):
    _app, client = app_client
    token = _login_admin(client)
    rid = _create_requirement(client, token)

    resp = _api(client, action="REQUIREMENT_SUBMIT", token=token, data={"requirementId": rid})
    body = resp.get_json()

    assert resp.status_code == 200
    assert body["ok"] is True
    assert body["data"]["requirementId"] == rid
    assert body["data"]["fromStatus"] == "DRAFT"
    assert body["data"]["toStatus"] == "SUBMITTED"

