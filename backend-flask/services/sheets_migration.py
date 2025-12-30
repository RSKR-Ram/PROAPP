from __future__ import annotations

import argparse
import csv
import os
from typing import Any, Iterable

from dotenv import load_dotenv
from sqlalchemy import select

import db as db_
from config import Config
from models import (
    AssignedTraining,
    AuditLog,
    Candidate,
    Employee,
    HoldLog,
    JobPosting,
    JobTemplate,
    JoinLog,
    OnlineTest,
    Permission,
    Requirement,
    RequirementHistory,
    RejectionLog,
    Role,
    Session,
    Setting,
    TestDecisionLog,
    TrainingLog,
    TrainingMaster,
    User,
)


def _as_bool(value: Any) -> bool:
    s = str(value or "").strip().lower()
    if s in {"1", "true", "yes", "y"}:
        return True
    if s in {"0", "false", "no", "n"}:
        return False
    return False


def _as_int_or_none(value: Any) -> int | None:
    s = str(value or "").strip()
    if not s:
        return None
    s = s.replace(",", "")
    try:
        return int(float(s))
    except Exception:
        return None


def _model_columns(model) -> set[str]:
    return {c.name for c in model.__table__.columns}  # type: ignore[attr-defined]


def _read_csv_rows(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


def _upsert_permissions(db, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    for row in rows:
        perm_type = str(row.get("permType") or "").upper().strip()
        perm_key = str(row.get("permKey") or "").upper().strip()
        if not perm_type or not perm_key:
            continue
        existing = (
            db.execute(select(Permission).where(Permission.permType == perm_type).where(Permission.permKey == perm_key))
            .scalars()
            .first()
        )
        if not existing:
            existing = Permission(permType=perm_type, permKey=perm_key)
            db.add(existing)
        existing.rolesCsv = str(row.get("rolesCsv") or "")
        existing.enabled = _as_bool(row.get("enabled"))
        existing.updatedAt = str(row.get("updatedAt") or "")
        existing.updatedBy = str(row.get("updatedBy") or "")
        count += 1
    return count


def _bulk_insert_by_pk(db, model, rows: Iterable[dict[str, Any]], *, type_overrides: dict[str, str] | None = None) -> int:
    cols = _model_columns(model)
    type_overrides = type_overrides or {}
    count = 0
    for row in rows:
        payload: dict[str, Any] = {}
        for k, v in row.items():
            if k not in cols:
                continue
            kind = type_overrides.get(k, "")
            if kind == "bool":
                payload[k] = _as_bool(v)
            elif kind == "int":
                payload[k] = _as_int_or_none(v)
            else:
                payload[k] = str(v or "")
        if not payload:
            continue
        db.merge(model(**payload))
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Import Google Sheets CSV exports into the Flask DB (one-time migration).")
    parser.add_argument("--csv-dir", default="./csv", help="Directory containing CSV exports named like sheet tabs (e.g. Users.csv).")
    args = parser.parse_args()

    load_dotenv()
    cfg = Config()
    engine = db_.init_engine(cfg.DATABASE_URL)

    from models import Base  # ensure models are registered

    Base.metadata.create_all(bind=engine)
    if db_.SessionLocal is None:
        raise RuntimeError("DB not initialized")

    session = db_.SessionLocal()
    try:
        csv_dir = args.csv_dir
        if not os.path.isdir(csv_dir):
            raise SystemExit(f"CSV dir not found: {csv_dir}")

        tasks: list[tuple[str, Any, dict[str, str] | None]] = [
            ("Users", User, None),
            ("Roles", Role, None),
            ("Settings", Setting, None),
            ("JobTemplates", JobTemplate, None),
            ("Requirements", Requirement, {"requiredCount": "int", "joinedCount": "int"}),
            ("RequirementHistory", RequirementHistory, None),
            ("JobPosting", JobPosting, None),
            (
                "Candidates",
                Candidate,
                {
                    "requiredCount": "int",
                    "joinedCount": "int",
                    "notPickCount": "int",
                    "onlineTestScore": "int",
                    "inPersonMarks": "int",
                    "tallyMarks": "int",
                    "voiceMarks": "int",
                    "excelMarks": "int",
                    "candidate_test_failed_but_manually_continued": "bool",
                },
            ),
            ("Sessions", Session, None),
            ("AuditLog", AuditLog, None),
            ("Logs_Rejection", RejectionLog, None),
            ("Logs_Hold", HoldLog, None),
            ("Logs_Join", JoinLog, None),
            ("OnlineTests", OnlineTest, {"score": "int"}),
            ("Employees", Employee, None),
            ("Trainings_Master", TrainingMaster, None),
            ("Assigned_Trainings", AssignedTraining, None),
            ("Training_Logs", TrainingLog, None),
            ("Logs_TestDecision", TestDecisionLog, None),
        ]

        total = 0
        for sheet_name, model, overrides in tasks:
            path = os.path.join(csv_dir, f"{sheet_name}.csv")
            if not os.path.exists(path):
                continue
            rows = _read_csv_rows(path)
            if sheet_name == "Permissions":
                total += _upsert_permissions(session, rows)
            else:
                total += _bulk_insert_by_pk(session, model, rows, type_overrides=overrides)

        # Permissions: special-case, because DB uses autoincrement id.
        perm_path = os.path.join(csv_dir, "Permissions.csv")
        if os.path.exists(perm_path):
            total += _upsert_permissions(session, _read_csv_rows(perm_path))

        session.commit()
        print(f"Imported/updated rows: {total}")
    finally:
        session.close()


if __name__ == "__main__":
    main()

