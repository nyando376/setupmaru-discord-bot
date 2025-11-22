import os
import urllib.parse
import asyncio
import logging
from typing import Optional, List
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

# 데이터베이스 연결 후보를 탐색하고 세션을 제공하는 핵심 헬퍼 모듈입니다.
log = logging.getLogger("bot.db")


def _env(*keys: str) -> Optional[str]:
    for k in keys:
        v = os.getenv(k)
        if v:
            return v
    return None


def _is_mysql(url: str) -> bool:
    return isinstance(url, str) and url.startswith((
        "mysql://",
        "mysql+mysqlconnector://",
        "mysql+pymysql://",
    ))


def _to_mysqlconnector_url(url: str) -> str:
    # Normalize to mysql+mysqlconnector and attach options
    if url.startswith("mysql+mysqlconnector://"):
        out = url
    elif url.startswith(("mysql://", "mysql+pymysql://")):
        out = url.replace("mysql+pymysql://", "mysql+mysqlconnector://", 1).replace(
            "mysql://", "mysql+mysqlconnector://", 1
        )
    else:
        out = url
    if "charset=" not in out:
        out += ("&" if "?" in out else "?") + "charset=utf8mb4"
    if "connection_timeout=" not in out and "connect_timeout=" not in out:
        out += ("&" if "?" in out else "?") + "connection_timeout=10"
    return out


def _build_database_candidates() -> List[str]:
    candidates: List[str] = []
    # 1) direct URLs
    for env_key in ("MYSQL_URL", "DATABASE_URL", "MYSQL_PUBLIC_URL", "MYSQL_PRIVATE_URL"):
        url = _env(env_key)
        if url and _is_mysql(url):
            candidates.append(_to_mysqlconnector_url(url))
    # 2) composed from parts
    host = _env("MYSQLHOST", "MYSQL_HOST")
    port = _env("MYSQLPORT", "MYSQL_PORT") or "3306"
    database = _env("MYSQLDATABASE", "MYSQL_DATABASE", "MYSQL_DB") or "railway"
    user = _env("MYSQLUSER", "MYSQL_USER")
    password = _env("MYSQLPASSWORD", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD")
    if host and user and password:
        u = urllib.parse.quote(user, safe="")
        p = urllib.parse.quote(password, safe="")
        candidates.append(_to_mysqlconnector_url(f"mysql+mysqlconnector://{u}:{p}@{host}:{port}/{database}"))
    # 3) local fallback (if password exists)
    if not candidates and password:
        p = urllib.parse.quote(password, safe="")
        candidates.append(_to_mysqlconnector_url(f"mysql+mysqlconnector://root:{p}@localhost:3306/discord_bot"))
    # dedupe
    uniq, seen = [], set()
    for u in candidates:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq


DB_CANDIDATES = _build_database_candidates()
CONNECT_ARGS = {} if os.getenv("MYSQL_SSL") != "1" else {"ssl_disabled": False}

Base = declarative_base()
TABLE_KW = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

engine = None
SessionLocal = None
resolved_url: Optional[str] = None


def _try_engine_connection(url: str):
    eng = create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_size=5,
        max_overflow=10,
        echo=False,
        future=True,
        connect_args=CONNECT_ARGS,
    )
    with eng.connect() as conn:
        conn.execute(text("SELECT 1"))
    return eng


def _sync_database_init(url: str):
    global engine, SessionLocal, resolved_url
    from . import models  # ensure models are imported so metadata is populated
    eng = _try_engine_connection(url)
    models.Base.metadata.create_all(bind=eng)
    engine = eng
    SessionLocal = sessionmaker(
        bind=engine, autocommit=False, autoflush=False, future=True, expire_on_commit=False
    )
    resolved_url = url


async def init_database(max_attempts_per_url: int = 3, delay: float = 1.5):
    last_error = None
    for url in DB_CANDIDATES:
        try:
            host = url.split("@", 1)[1].split("/", 1)[0]
        except Exception:
            host = "(unknown)"
        for attempt in range(1, max_attempts_per_url + 1):
            try:
                await asyncio.to_thread(_sync_database_init, url)
                log.info(f"✅ DB connected: {host}")
                return
            except Exception as e:
                last_error = e
                log.warning(f"DB connect fail {attempt}/{max_attempts_per_url} for {host}: {e}")
                if attempt < max_attempts_per_url:
                    await asyncio.sleep(round(delay * attempt, 2))
        log.warning(f"Switch DB candidate: {host}")
    raise RuntimeError(f"DB init failed. Last error: {last_error}")


@contextmanager
def session_scope():
    if SessionLocal is None:
        raise RuntimeError("Database not initialized")
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
