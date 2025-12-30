from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

engine = None
SessionLocal = sessionmaker(autocommit=False, autoflush=False, future=True)


def init_engine(database_url: str):
    global engine

    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    engine = create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    SessionLocal.configure(bind=engine)
    return engine
