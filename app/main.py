import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, Tuple, TypeVar, cast

from flask import Flask, Response, jsonify, request
from flask.typing import ResponseReturnValue

from app.telemetry import setup as telemetry_setup

app = Flask(__name__)
if os.getenv("OTEL_SDK_DISABLED", "").lower() not in {"true", "1"}:
    telemetry_setup(app, service_name="keep-app")

F = TypeVar("F", bound=Callable[..., ResponseReturnValue])


def route(rule: str, **options: Any) -> Callable[[F], F]:
    return cast(Callable[[F], F], app.route(rule, **options))


@contextmanager
def record_route_metrics(route: str) -> Generator[None, None, None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        logging.getLogger(__name__).info(
            "route completed",
            extra={"route": route, "duration_ms": round(duration_ms, 2)},
        )


@route("/health")
def health() -> Dict[str, str]:
    with record_route_metrics("health"):
        return {"status": "ok"}


@route("/")
def index() -> str:
    with record_route_metrics("index"):
        cert_subject = request.headers.get("X-Client-Subject", "unknown") or "unknown"
        if cert_subject.startswith("Subject="):
            cert_subject = cert_subject.replace("Subject=", "", 1)
        device_id = request.headers.get("X-Device-ID", "unknown") or "unknown"
        return (
            f"Hello from keep protected app!\n"
            f"Client cert subject: {cert_subject}\n"
            f"Device ID: {device_id}\n"
        )


@route("/step-up", methods=["POST"])
def step_up() -> Tuple[Response, int]:
    with record_route_metrics("step_up"):
        return jsonify({"status": "step-up required"}), 202
