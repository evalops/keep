from __future__ import annotations

import logging
import os
from typing import Optional

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_logger = logging.getLogger(__name__)


def _resource(service_name: str, environment: str) -> Resource:
    return Resource.create({
        "service.name": service_name,
        "deployment.environment": environment,
    })


def init_tracing(service_name: str, environment: str, endpoint: str, insecure: bool) -> None:
    exporter = OTLPSpanExporter(endpoint=endpoint or None, insecure=insecure)
    tracer_provider = TracerProvider(resource=_resource(service_name, environment))
    tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)


def init_metrics(service_name: str, environment: str, endpoint: str, insecure: bool) -> None:
    exporter = OTLPMetricExporter(endpoint=endpoint or None, insecure=insecure)
    reader = PeriodicExportingMetricReader(exporter)
    provider = MeterProvider(resource=_resource(service_name, environment), metric_readers=[reader])
    metrics.set_meter_provider(provider)


def instrument_flask_app(app) -> None:
    FlaskInstrumentor().instrument_app(app)


def setup(app, service_name: str, environment: Optional[str] = None) -> None:
    environment = environment or os.getenv("APP_ENV", "dev")
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"

    try:
        init_tracing(service_name, environment, endpoint, insecure)
        init_metrics(service_name, environment, endpoint, insecure)
        instrument_flask_app(app)
    except Exception:  # pragma: no cover - best effort initialization
        _logger.exception("failed to initialize telemetry")
