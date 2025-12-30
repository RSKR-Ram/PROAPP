from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cachetools import TTLCache
from dateutil import parser as dt_parser
from zoneinfo import ZoneInfo

ALLOWED_ERROR_CODES = {
    "BAD_REQUEST",
    "AUTH_INVALID",
    "FORBIDDEN",
    "NOT_FOUND",
    "CONFLICT",
    "INTERNAL",
}

_CODE_MAP = {
    "BAD_JSON": "BAD_REQUEST",
    "CONFIG_MISSING": "INTERNAL",
    "SCHEMA_MISSING": "INTERNAL",
    "UNKNOWN_ERROR": "INTERNAL",
    "ACTION_NOT_IMPLEMENTED": "BAD_REQUEST",
    "AUTH_REQUIRED": "AUTH_INVALID",
    "AUTH_INVALID_ID_TOKEN": "AUTH_INVALID",
    "AUTH_INVALID_AUDIENCE": "AUTH_INVALID",
    "AUTH_EMAIL_NOT_VERIFIED": "AUTH_INVALID",
    "AUTH_USER_NOT_ALLOWED": "AUTH_INVALID",
    "AUTH_USER_DISABLED": "AUTH_INVALID",
    "RBAC_DENIED": "FORBIDDEN",
}


def map_error_code(code: str) -> str:
    c = str(code or "").upper().strip()
    if c in ALLOWED_ERROR_CODES:
        return c
    return _CODE_MAP.get(c, "INTERNAL")


class ApiError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 200):
        super().__init__(message)
        self.code = map_error_code(code)
        self.message = str(message or "")
        self.http_status = http_status


def ok(data: Any, http_status: int = 200):
    return {"ok": True, "data": data}, http_status


def err(code: str, message: str, http_status: int = 200):
    return {"ok": False, "error": {"code": map_error_code(code), "message": str(message or "")}}, http_status


def iso_utc_now() -> str:
    dt = datetime.now(timezone.utc)
    # Match JS Date.toJSON() millisecond precision.
    dt = dt.replace(microsecond=(dt.microsecond // 1000) * 1000)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_iso_utc(dt: datetime) -> str:
    x = dt.astimezone(timezone.utc)
    x = x.replace(microsecond=(x.microsecond // 1000) * 1000)
    return x.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_datetime_maybe(value: Any, *, app_timezone: str = "Asia/Kolkata") -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value or "").strip()
        if not s:
            return None
        try:
            dt = dt_parser.parse(s)
        except Exception:
            return None

    if dt.tzinfo is None:
        try:
            dt = dt.replace(tzinfo=ZoneInfo(app_timezone))
        except Exception:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_uuid() -> str:
    return str(uuid.uuid4())


def new_log_id() -> str:
    return f"LOG-{new_uuid()}"


def parse_json_body(raw_text: str) -> dict:
    try:
        obj = json.loads(raw_text or "{}")
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid JSON body")
    if not isinstance(obj, dict):
        raise ApiError("BAD_REQUEST", "JSON body must be an object")
    return obj


def safe_json_string(value: Any, fallback: str = "") -> str:
    try:
        return json.dumps(value)
    except Exception:
        return fallback


def redact_for_audit(obj: Any) -> Any:
    if not obj or not isinstance(obj, (dict, list)):
        return obj
    try:
        copy = json.loads(json.dumps(obj))
    except Exception:
        return obj
    if isinstance(copy, dict) and "base64" in copy:
        copy["base64"] = "[REDACTED]"
    if isinstance(copy, dict) and isinstance(copy.get("docs"), list):
        docs = []
        for d in copy["docs"]:
            if isinstance(d, dict) and "base64" in d:
                x = dict(d)
                x["base64"] = "[REDACTED]"
                docs.append(x)
            else:
                docs.append(d)
        copy["docs"] = docs
    if isinstance(copy, dict) and isinstance(copy.get("items"), list):
        copy["items"] = f"[OMITTED:{len(copy['items'])}]"
    return copy


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1F\x7F]")
_WINDOWS_FORBIDDEN_RE = re.compile(r"[\\/:*?\"<>|]+")


def sanitize_filename(name: str) -> str:
    s = str(name or "").strip()
    s = _CONTROL_CHARS_RE.sub("", s)
    s = _WINDOWS_FORBIDDEN_RE.sub("_", s)
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"_+", "_", s)
    if not s or s in {".", ".."}:
        s = "file"
    if len(s) > 120:
        s = s[:120]
    return s


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def decode_base64_to_bytes(b64: str) -> bytes:
    try:
        return base64.b64decode(b64, validate=True)
    except Exception:
        raise ApiError("BAD_REQUEST", "Invalid base64")


@dataclass(frozen=True)
class AuthContext:
    valid: bool
    userId: str
    email: str
    role: str
    expiresAt: str


def normalize_role(role: Any) -> Optional[str]:
    r = str(role or "").strip().upper()
    return r or None


def parse_roles_csv(roles_csv: str) -> list[str]:
    s = str(roles_csv or "")
    parts = [normalize_role(p) for p in s.split(",")]
    return [p for p in parts if p]


class SimpleRateLimiter:
    def __init__(self):
        self._counts = TTLCache(maxsize=50_000, ttl=60)

    @staticmethod
    def _parse_limit_per_minute(limit: str) -> int:
        m = re.match(r"^\s*(\d+)\s+per\s+minute\s*$", str(limit or ""), re.IGNORECASE)
        if not m:
            return 300
        return int(m.group(1))

    def check(self, key: str, limit: str) -> None:
        max_per_minute = self._parse_limit_per_minute(limit)
        current = int(self._counts.get(key, 0)) + 1
        self._counts[key] = current
        if current > max_per_minute:
            raise ApiError("CONFLICT", "Rate limit exceeded", http_status=429)


def now_monotonic() -> float:
    return time.monotonic()
