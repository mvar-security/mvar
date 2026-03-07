#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

die() {
  printf "[run-python][ERROR] %s\n" "$*" >&2
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

  die "No Python interpreter found. Install Python 3.10+ or run bash scripts/install.sh"
}

[[ $# -gt 0 ]] || die "Usage: bash scripts/run-python.sh <python args...>"

PYTHON_BIN="$(pick_python)"
cd "$REPO_ROOT"
exec "$PYTHON_BIN" "$@"
