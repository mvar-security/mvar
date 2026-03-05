"""
MVAR observability helpers (Prometheus + OpenTelemetry).

All observability behavior is additive and gated by env flags:
- MVAR_ENABLE_PROMETHEUS_METRICS=1
- MVAR_ENABLE_OTEL_TRACING=1

If dependencies are unavailable, the module degrades to no-op behavior.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server
except Exception:  # pragma: no cover - optional runtime dependency
    Counter = None  # type: ignore[assignment]
    Gauge = None  # type: ignore[assignment]
    Histogram = None  # type: ignore[assignment]
    start_http_server = None  # type: ignore[assignment]

try:
    from opentelemetry import trace
except Exception:  # pragma: no cover - optional runtime dependency
    trace = None  # type: ignore[assignment]


_PROM_METRICS: Optional[Dict[str, Any]] = None
_PROMETHEUS_STARTED_PORTS: set[int] = set()


def _to_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _to_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _sanitize_label(value: str, fallback: str = "unknown") -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in value.lower()).strip("_")
    return cleaned[:48] if cleaned else fallback


@dataclass
class _NoopSpan:
    def set_attribute(self, _key: str, _value: Any) -> None:
        return

    def add_event(self, _name: str, _attributes: Optional[Dict[str, Any]] = None) -> None:
        return

    def record_exception(self, _exc: BaseException) -> None:
        return


class MVARObservability:
    """Optional observability collector for policy runtime."""

    def __init__(
        self,
        *,
        enable_metrics: bool = False,
        enable_tracing: bool = False,
        engine: str = "real",
        prometheus_port: int = 0,
    ):
        self.enable_metrics = enable_metrics and Counter is not None and Histogram is not None and Gauge is not None
        self.enable_tracing = enable_tracing and trace is not None
        self.engine = _sanitize_label(engine, fallback="real")
        self.prometheus_port = prometheus_port
        self._metrics = self._get_metrics() if self.enable_metrics else None
        self._tracer = trace.get_tracer("mvar.runtime") if self.enable_tracing and trace is not None else None

        if self.enable_metrics and self.prometheus_port > 0 and start_http_server is not None:
            self._ensure_server_started(self.prometheus_port)

    @classmethod
    def from_env(cls) -> "MVARObservability":
        return cls(
            enable_metrics=_to_bool("MVAR_ENABLE_PROMETHEUS_METRICS", default=False),
            enable_tracing=_to_bool("MVAR_ENABLE_OTEL_TRACING", default=False),
            engine=os.getenv("MVAR_RUNTIME_ENGINE", "real"),
            prometheus_port=_to_int("MVAR_PROMETHEUS_PORT", default=0),
        )

    @staticmethod
    def _get_metrics() -> Dict[str, Any]:
        global _PROM_METRICS
        if _PROM_METRICS is None:
            _PROM_METRICS = {
                "verifications_total": Counter(
                    "mvar_verifications_total",
                    "Total MVAR verifications by trust level and runtime engine",
                    ["trust_level", "engine"],
                ),
                "verification_duration_seconds": Histogram(
                    "mvar_verification_duration_seconds",
                    "Duration of MVAR verification layers",
                    ["layer"],
                    buckets=[0.1, 0.5, 1.0, 2.0, 5.0],
                ),
                "verification_errors_total": Counter(
                    "mvar_verification_errors_total",
                    "Total MVAR verification errors by layer and error type",
                    ["layer", "error_type"],
                ),
                "drift_velocity": Gauge(
                    "mvar_drift_velocity",
                    "MVAR drift velocity signal (set by host runtime when available)",
                ),
            }
        return _PROM_METRICS

    @staticmethod
    def _ensure_server_started(port: int) -> None:
        if port in _PROMETHEUS_STARTED_PORTS:
            return
        try:
            start_http_server(port)
            _PROMETHEUS_STARTED_PORTS.add(port)
        except OSError:
            # Already bound or unavailable; keep runtime non-fatal.
            return

    @contextmanager
    def trace_layer(self, layer: str, attributes: Optional[Dict[str, Any]] = None):
        start = time.perf_counter()
        if self._tracer is None:
            span = _NoopSpan()
            try:
                yield span
            except Exception:
                self.record_error(layer, "exception")
                raise
            finally:
                self.observe_layer_duration(layer, time.perf_counter() - start)
            return

        with self._tracer.start_as_current_span(layer) as span:
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            try:
                yield span
            except Exception as exc:
                span.record_exception(exc)
                self.record_error(layer, "exception")
                raise
            finally:
                duration = time.perf_counter() - start
                span.set_attribute("mvar.layer.duration_seconds", duration)
                self.observe_layer_duration(layer, duration)

    def observe_layer_duration(self, layer: str, duration_seconds: float) -> None:
        if not self._metrics:
            return
        self._metrics["verification_duration_seconds"].labels(
            layer=_sanitize_label(layer, fallback="sdk")
        ).observe(max(duration_seconds, 0.0))

    def record_error(self, layer: str, error_type: str) -> None:
        if not self._metrics:
            return
        self._metrics["verification_errors_total"].labels(
            layer=_sanitize_label(layer, fallback="sdk"),
            error_type=_sanitize_label(error_type, fallback="unknown"),
        ).inc()

    def record_verification(self, trust_level: str, outcome: str) -> None:
        if not self._metrics:
            return
        del outcome  # outcome is captured through traces and logs; keep metric cardinality bounded.
        self._metrics["verifications_total"].labels(
            trust_level=_sanitize_label(trust_level, fallback="unknown"),
            engine=self.engine,
        ).inc()

    def set_drift_velocity(self, value: float) -> None:
        if not self._metrics:
            return
        self._metrics["drift_velocity"].set(value)
