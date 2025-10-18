import os
import time

import pytest

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


def _sqlstate(exc: Exception) -> str | None:
    code = getattr(exc, "pgcode", None)
    if isinstance(code, str):
        return code
    code = getattr(exc, "sqlstate", None)
    return code if isinstance(code, str) else None


def wait_for_database(dsn: str, timeout: float = 30.0) -> None:
    try:
        import psycopg  # type: ignore
    except ImportError as exc:  # pragma: no cover - developer misconfiguration
        raise RuntimeError("psycopg is required for database tests") from exc

    deadline = time.monotonic() + timeout
    attempt = 0

    while True:
        attempt += 1
        try:
            with psycopg.connect(dsn, connect_timeout=3) as conn:  # type: ignore[attr-defined]
                with conn.cursor() as cur:  # type: ignore[attr-defined]
                    cur.execute("SELECT 1")
                return
        except Exception as exc:  # pragma: no cover - transient failures
            code = _sqlstate(exc)
            if isinstance(code, str) and code.startswith("28"):
                raise RuntimeError(f"Database authentication failed (SQLSTATE {code}): {exc}") from exc
            if code and code not in TRANSIENT_CODES:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Database not ready after {timeout}s (last error: {exc})") from exc
            time.sleep(min(0.25 * attempt, 2.0))


@pytest.fixture(scope="session", autouse=True)
def _ensure_database_ready() -> None:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError(
            "DATABASE_URL is required for tests. Set it to postgresql://postgres:postgres@127.0.0.1:5432/app_test"
        )
    wait_for_database(dsn)
