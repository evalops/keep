import logging
import time
from contextlib import contextmanager

from flask import Flask, jsonify, request

from app.telemetry import setup as telemetry_setup

app = Flask(__name__)
telemetry_setup(app, service_name="keep-app")


@contextmanager
def record_route_metrics(route: str):
    start = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        logging.getLogger(__name__).info(
            "route completed",
            extra={"route": route, "duration_ms": round(duration_ms, 2)},
        )


@app.route("/health")
def health():
    with record_route_metrics("health"):
        return {"status": "ok"}


@app.route("/")
def index():
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


@app.route("/step-up", methods=["POST"])
def step_up():
    with record_route_metrics("step_up"):
        return jsonify({"status": "step-up required"}), 202
