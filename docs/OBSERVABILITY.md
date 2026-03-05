# MVAR Observability

MVAR provides optional observability for verification runtime behavior:

- Prometheus metrics endpoint
- OpenTelemetry tracing spans

These features are additive and do not change policy enforcement semantics.

## Enable Prometheus Metrics

Environment flags:

```bash
export MVAR_ENABLE_PROMETHEUS_METRICS=1
export MVAR_PROMETHEUS_PORT=8000
```

Metrics exposed:

- `mvar_verifications_total{trust_level,engine}`
- `mvar_verification_duration_seconds{layer}`
- `mvar_verification_errors_total{layer,error_type}`
- `mvar_drift_velocity`

Run demo:

```bash
python examples/metrics_demo.py
curl http://localhost:8000/metrics
```

## Enable OpenTelemetry Tracing

Environment flag:

```bash
export MVAR_ENABLE_OTEL_TRACING=1
```

Run demo (console exporter):

```bash
python examples/otel_demo.py
```

The demo configures a local console span exporter and emits spans for key verification stages.

## Install Notes

Observability dependencies are included in core installation and also available via extra:

```bash
python -m pip install .[observability]
```
