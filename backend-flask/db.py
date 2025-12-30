from __future__ import annotations

import socket

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

engine = None
SessionLocal = sessionmaker(autocommit=False, autoflush=False, future=True)


def init_engine(database_url: str):
    global engine

    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    # Some hosts (e.g. Render) may not have IPv6 connectivity. If DNS returns an IPv6
    # address first for Supabase, psycopg2 can fail with "Network is unreachable".
    # For Supabase Postgres, resolve an IPv4 address and pass it as `hostaddr` while
    # keeping the hostname in the URL.
    try:
        if (
            (database_url.startswith("postgresql") or database_url.startswith("postgres"))
            and "supabase.co" in database_url
        ):
            u = make_url(database_url)
            host = u.host
            port = int(u.port or 5432)
            if host:
                infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
                if infos:
                    ipv4 = infos[0][4][0]
                    connect_args = {**connect_args, "hostaddr": ipv4}
    except Exception:
        pass

    engine = create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    SessionLocal.configure(bind=engine)
    return engine
