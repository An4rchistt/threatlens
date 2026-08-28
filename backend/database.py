"""SQLAlchemy engine, session factory and bootstrap helpers.

The whole persistence layer is intentionally synchronous: scan volume is low
(one row per analysed URL) and FastAPI endpoints push the blocking calls onto
the threadpool via ``fastapi.concurrency.run_in_threadpool``. That keeps the
event loop free for Playwright and the outbound HTTP calls without dragging an
async driver into the dependency tree.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

LOGGER = logging.getLogger("threatlens.database")

DEFAULT_DATABASE_URL = (
    "postgresql+psycopg2://threatlens:threatlens_dev_password@postgres:5432/threatlens"
)

_TRUTHY = {"1", "true", "yes", "on", "y"}


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in _TRUTHY


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning("Invalid integer for %s=%r - falling back to %s", name, raw, default)
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        LOGGER.warning("Invalid float for %s=%r - falling back to %s", name, raw, default)
        return default


def normalise_database_url(raw: str) -> str:
    """Coerce common DSN spellings into an explicit SQLAlchemy driver URL.

    Managed providers hand out ``postgres://`` URLs which SQLAlchemy 2.x no
    longer accepts, so they are rewritten to the psycopg2 dialect.
    """

    url = (raw or "").strip()
    if not url:
        return DEFAULT_DATABASE_URL
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg2://" + url[len("postgresql://") :]
    return url


DATABASE_URL: str = normalise_database_url(os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL))
IS_SQLITE: bool = DATABASE_URL.startswith("sqlite")
IS_POSTGRES: bool = DATABASE_URL.startswith("postgresql")

SQL_ECHO: bool = _env_flag("SQL_ECHO", "0")
POOL_SIZE: int = _env_int("DB_POOL_SIZE", 5)
MAX_OVERFLOW: int = _env_int("DB_MAX_OVERFLOW", 10)
POOL_TIMEOUT: int = _env_int("DB_POOL_TIMEOUT", 30)
POOL_RECYCLE: int = _env_int("DB_POOL_RECYCLE", 1800)
CONNECT_TIMEOUT: int = _env_int("DB_CONNECT_TIMEOUT", 10)
CONNECT_RETRIES: int = _env_int("DB_CONNECT_RETRIES", 20)
CONNECT_RETRY_DELAY: float = _env_float("DB_CONNECT_RETRY_DELAY", 2.0)


def _build_engine() -> Engine:
    """Create the process-wide engine with dialect-appropriate settings."""

    if IS_SQLITE:
        # Used for local unit runs / offline development: a single shared
        # in-process connection keeps ``:memory:`` databases usable across the
        # FastAPI threadpool.
        return create_engine(
            DATABASE_URL,
            echo=SQL_ECHO,
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool if ":memory:" in DATABASE_URL else None,
        )

    connect_args: Dict[str, Any] = {}
    if IS_POSTGRES:
        connect_args = {
            "connect_timeout": CONNECT_TIMEOUT,
            "application_name": "threatlens-backend",
            # Abort any statement that somehow runs longer than 30s so a stuck
            # query can never wedge a request worker.
            "options": "-c statement_timeout=30000",
        }

    return create_engine(
        DATABASE_URL,
        echo=SQL_ECHO,
        future=True,
        pool_pre_ping=True,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_timeout=POOL_TIMEOUT,
        pool_recycle=POOL_RECYCLE,
        connect_args=connect_args,
    )


engine: Engine = _build_engine()

SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model in the platform."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped session."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional context manager: commit on success, roll back on error."""

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def wait_for_database(
    retries: int | None = None,
    delay: float | None = None,
) -> bool:
    """Block until the database answers ``SELECT 1`` or the budget runs out.

    Compose health checks already gate startup, but a restarting Postgres can
    still refuse connections for a few seconds. Returning a bool (instead of
    raising) lets the API boot in a degraded, clearly-reported state.
    """

    attempts = CONNECT_RETRIES if retries is None else retries
    pause = CONNECT_RETRY_DELAY if delay is None else delay

    for attempt in range(1, max(attempts, 1) + 1):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            LOGGER.info("Database connection established (attempt %s).", attempt)
            return True
        except SQLAlchemyError as exc:
            root = getattr(exc, "orig", exc)
            LOGGER.warning(
                "Database not ready (attempt %s/%s): %s", attempt, attempts, root
            )
            if attempt >= attempts:
                LOGGER.error("Giving up waiting for the database after %s attempts.", attempts)
                return False
            time.sleep(pause)
    return False


def init_db() -> bool:
    """Create every table declared on :class:`Base` if it does not exist."""

    # Imported here (not at module scope) so the ORM models can import `Base`
    # from this module without a circular import.
    from models import ScanHistory  # noqa: F401  (registers the mapping)

    if not wait_for_database():
        return False

    try:
        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError as exc:
        LOGGER.error("Failed to create database schema: %s", getattr(exc, "orig", exc))
        return False

    LOGGER.info(
        "Database schema ready (tables: %s).",
        ", ".join(sorted(Base.metadata.tables)) or "none",
    )
    return True


def database_status() -> Dict[str, Any]:
    """Health-check payload describing connectivity without leaking secrets."""

    status: Dict[str, Any] = {
        "dialect": engine.dialect.name,
        "connected": False,
        "latency_ms": None,
        "error": None,
    }
    started = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        status["connected"] = True
        status["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    except SQLAlchemyError as exc:
        status["error"] = str(getattr(exc, "orig", exc))[:300]
    return status


def dispose_engine() -> None:
    """Release pooled connections during application shutdown."""

    engine.dispose()
    LOGGER.info("Database connection pool disposed.")


def safe_database_target() -> str:
    """``host:port/database`` for logs, with credentials stripped."""

    url = engine.url
    host = url.host or "local"
    port = f":{url.port}" if url.port else ""
    database = url.database or ""
    return f"{host}{port}/{database}"
