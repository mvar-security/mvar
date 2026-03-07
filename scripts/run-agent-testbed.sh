#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TESTBED_SCRIPT="$REPO_ROOT/examples/agent_testbed.py"

die() {
  printf "[run-agent-testbed][ERROR] %s\n" "$*" >&2
  exit 1
}

pick_python() {
  if [[ -n "${MVAR_PYTHON:-}" ]]; then
    [[ -x "${MVAR_PYTHON}" ]] || die "MVAR_PYTHON is set but not executable: ${MVAR_PYTHON}"
    printf "%s\n" "${MVAR_PYTHON}"
    return
  fi

  if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    printf "%s\n" "$REPO_ROOT/.venv/bin/python"
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return
  fi

  if command -v python >/dev/null 2>&1; then
    command -v python
    return
  fi

  die "No Python interpreter found. Install Python 3.10+ or create .venv in the repo root."
}

[[ -f "$TESTBED_SCRIPT" ]] || die "Missing testbed script at $TESTBED_SCRIPT"

PYTHON_BIN="$(pick_python)"

# Default to the headline attack scenario if no args are provided.
if [[ $# -eq 0 ]]; then
  set -- --scenario rag_injection
fi

cd "$REPO_ROOT"
exec "$PYTHON_BIN" "$TESTBED_SCRIPT" "$@"
