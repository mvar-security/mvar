# MVAR Adapter Conformance Kit

This folder provides a reusable conformance harness for framework adapters.

## Files

- `adapter_contract.py`: required adapter interface (Protocol + decision types)
- `pytest_adapter_harness.py`: pytest test template for adapter security conformance
- `openclaw_contract.py`: OpenClaw/ClawBot-specific gateway security contract
- `pytest_openclaw_harness.py`: OpenClaw/ClawBot conformance tests (gatewayUrl + token boundary)
- `community_attack_vector_schema.json`: schema for community-submitted attack vectors
- `community_attack_harness.py`: runner for validating community attack submissions

## Intended workflow

1. In your adapter repo, vendor/copy this folder (or install it as a test dependency).
2. Implement `adapter` fixture in the pytest harness.
3. Ensure your adapter routes all sink execution through:
   - `evaluate(...)`
   - `authorize_execution(...)`
4. Run:

```bash
pytest -q tests/test_mvar_adapter_conformance.py
```

## CI recommendation

Make this conformance suite mandatory for adapter release pipelines.
