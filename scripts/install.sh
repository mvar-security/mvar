#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PATH="${VENV_PATH:-$REPO_ROOT/.venv}"

log() { printf "[install] %s\n" "$*"; }
die() { printf "[install][ERROR] %s\n" "$*" >&2; exit 1; }

pick_base_python() {
  if [[ -n "${MVAR_PYTHON:-}" ]] && [[ -x "${MVAR_PYTHON}" ]]; then
    printf "%s\n" "${MVAR_PYTHON}"
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

  die "No Python found. Install Python 3.10+ and rerun."
}

BASE_PY="$(pick_base_python)"

if [[ ! -x "$VENV_PATH/bin/python" ]]; then
  log "Creating virtual environment at $VENV_PATH"
  "$BASE_PY" -m venv "$VENV_PATH"
fi

PYTHON_BIN="$VENV_PATH/bin/python"
[[ -x "$PYTHON_BIN" ]] || die "Virtualenv python not found at $PYTHON_BIN"

if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
  log "Bootstrapping pip with ensurepip"
  "$PYTHON_BIN" -m ensurepip --upgrade
fi

log "Upgrading packaging tools"
"$PYTHON_BIN" -m pip install -U pip setuptools wheel

log "Installing mvar package + test runner"
"$PYTHON_BIN" -m pip install . pytest

log "Install complete"
printf "\nNext steps:\n"
printf "  1) bash scripts/run-agent-testbed.sh --scenario rag_injection\n"
printf "  2) bash scripts/launch-gate.sh\n"
