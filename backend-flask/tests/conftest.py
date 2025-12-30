import os
import sys
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture()
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "test.db"

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-google-client-id")
    monkeypatch.setenv("AUTH_ALLOW_TEST_TOKENS", "1")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")

    # Prevent accidental pollution from any existing env config.
    monkeypatch.delenv("UPLOAD_DIR", raising=False)
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)

    from app import create_app

    app = create_app()
    app.testing = True

    with app.test_client() as client:
        yield app, client

