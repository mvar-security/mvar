# OpenAI Deployment Cookbook (Docker)

This cookbook is the Milestone 1 deployment baseline for deeper OpenAI integration.

## Goal
Run an OpenAI-style tool-dispatch loop with MVAR enforcement enabled inside Docker.

## Prerequisites
- Docker Desktop or Docker Engine
- Python 3.11+
- Repo checkout

## 1) Build image

```bash
cd <repo-root>
docker build -f examples/deployment/openai_docker/Dockerfile -t mvar-openai-runtime:local .
```

## 2) Run container

```bash
docker run --rm \
  -e MVAR_REQUIRE_EXECUTION_TOKEN=1 \
  -e MVAR_EXEC_TOKEN_SECRET=change_me_in_prod \
  -e MVAR_FAIL_CLOSED=1 \
  mvar-openai-runtime:local
```

## 3) Expected output
- The demo payload includes one low-risk call and one critical shell call.
- Low-risk call should execute.
- Critical untrusted call should be blocked.
- Final line prints a batch summary with `executed_calls=1` and `blocked_calls=1`.

## 4) Security assumptions
- Container runtime hardening (read-only rootfs, dropped capabilities) is still required.
- MVAR enforces sink boundaries; it does not replace OS sandboxing.
- Keep `MVAR_EXEC_TOKEN_SECRET` in a secret store (not hardcoded).

## 5) Failure modes and troubleshooting

### `PermissionError: STEP_UP required before execution`
- You are running with strict mode and a sink is requiring step-up.
- For non-interactive runtime flows, keep strict mode disabled or add explicit approval handling.

### `Execution token required`
- Verify `MVAR_REQUIRE_EXECUTION_TOKEN=1` and `MVAR_EXEC_TOKEN_SECRET` are set together.

### `Unknown tool call`
- Ensure tool names in model output match your `tool_registry` keys.

## 6) Validation before rollout

Run from repo root:

```bash
./scripts/launch-gate.sh
python3 ./scripts/check_agent_testbed_trilogy.py
pytest -q tests/test_openai_deep_integration.py
```

## 7) Rollback guidance
- Revert to previous known-good container tag.
- Re-run trilogy + launch gate before promoting.
- Compare policy hash and trace fields in logs to verify expected behavior.
