import os
import time
from typing import Any, Callable, Optional, TypeVar, cast
from urllib.parse import quote_plus

import pytest

os.environ.setdefault("OTEL_SDK_DISABLED", "true")

F = TypeVar("F", bound=Callable[..., object])


def typed_fixture(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    """Typed veneer over pytest.fixture to keep mypy happy while preserving runtime behavior."""
    fixture_factory = pytest.fixture(*args, **kwargs)

    def decorator(func: F) -> F:
        return cast(F, fixture_factory(func))

    return decorator

TRANSIENT_CODES = {
    "08000",
    "08001",
    "08003",
    "08004",
    "08006",
    "08007",
    "08P01",
    "57P03",
}

DEFAULT_DSN = "postgresql://postgres:postgres@127.0.0.1:5432/app_test"
# Set APP_TEST_REQUIRE_DB=1 to run Flask integration tests against a live
# Postgres instance. By default the tests stub out database checks so they can
# run in isolated environments such as CI.
REQUIRE_DATABASE = os.getenv("APP_TEST_REQUIRE_DB") == "1"


def _sqlstate(exc: Exception) -> Optional[str]:
    code = getattr(exc, "pgcode", None)
    if isinstance(code, str):
        return code
    code = getattr(exc, "sqlstate", None)
    return code if isinstance(code, str) else None


def _build_dsn_from_pg_env() -> Optional[str]:
    user = os.getenv("PGUSER")
    host = os.getenv("PGHOST")
    database = os.getenv("PGDATABASE")
    if not user or not host or not database:
        return None

    password = os.getenv("PGPASSWORD", "")
    port = os.getenv("PGPORT", "5432")
    sslmode = os.getenv("PGSSLMODE")

    user_segment = quote_plus(user)
    auth = user_segment
    if password:
        auth = f"{user_segment}:{quote_plus(password)}"

    dsn = f"postgresql://{auth}@{host}:{port}/{database}"
    if sslmode:
        connector = "&" if "?" in dsn else "?"
        dsn = f"{dsn}{connector}sslmode={sslmode}"
    return dsn


def resolve_dsn() -> str:
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        return dsn

    env_dsn = _build_dsn_from_pg_env()
    if env_dsn:
        return env_dsn

    return DEFAULT_DSN


def wait_for_database(dsn: str, timeout: float = 30.0) -> None:
    if not REQUIRE_DATABASE:
        return

    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - developer misconfiguration
        raise RuntimeError("psycopg is required for database tests") from exc

    deadline = time.monotonic() + timeout
    attempt = 0

    while True:
        attempt += 1
        try:
            with psycopg.connect(dsn, connect_timeout=3) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                return
        except Exception as exc:  # pragma: no cover - transient failures
            code = _sqlstate(exc)
            if isinstance(code, str) and code.startswith("28"):
                raise RuntimeError(
                    f"Database authentication failed (SQLSTATE {code}): {exc}"
                ) from exc
            if code and code not in TRANSIENT_CODES:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Database not ready after {timeout}s (last error: {exc})"
                ) from exc
            time.sleep(min(0.25 * attempt, 2.0))


@typed_fixture(scope="session", autouse=True)
def _ensure_database_ready() -> None:
    wait_for_database(resolve_dsn())
