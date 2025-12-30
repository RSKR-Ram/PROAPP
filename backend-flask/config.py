import os


class Config:
    def __init__(self) -> None:
        self.APP_ENV = os.getenv("APP_ENV", "development")
        self.HOST = os.getenv("HOST", "0.0.0.0")
        self.PORT = int(os.getenv("PORT", "5002"))

        database_url = (os.getenv("DATABASE_URL", "sqlite:///./hrms.db") or "").strip()

        # Supabase Postgres requires SSL. If the user pastes a URL without sslmode,
        # default to sslmode=require for Supabase hosts.
        if (
            (database_url.startswith("postgresql://") or database_url.startswith("postgres://") or database_url.startswith("postgresql+"))
            and "sslmode=" not in database_url
            and "supabase.co" in database_url
        ):
            database_url += ("&" if "?" in database_url else "?") + "sslmode=require"

        self.DATABASE_URL = database_url

        self.GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
        self.SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "720"))
        self.APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Asia/Kolkata")

        self.ALLOWED_ORIGINS = [
            s.strip() for s in (os.getenv("ALLOWED_ORIGINS", "*") or "*").split(",") if s.strip()
        ]

        self.UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")

        self.RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "300 per minute")
        self.RATE_LIMIT_GLOBAL = os.getenv("RATE_LIMIT_GLOBAL", "2000 per minute")
        self.RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "30 per minute")

        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

        # Tests/dev only: bypass Google token verification.
        self.AUTH_ALLOW_TEST_TOKENS = os.getenv("AUTH_ALLOW_TEST_TOKENS", "0") == "1"
