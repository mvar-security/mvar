#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CURRENT_DIR="$(pwd)"
EXPECTED_VENV="$REPO_ROOT/.venv"

printf "MVAR environment doctor\n"
printf "  cwd: %s\n" "$CURRENT_DIR"
printf "  repo root: %s\n" "$REPO_ROOT"
PYTHON3_BIN="$(command -v python3 || true)"
printf "  python: %s\n" "${PYTHON3_BIN:-missing}"

if [[ -z "$PYTHON3_BIN" ]]; then
  printf "\n[ERROR] python3 not found in PATH.\n"
  printf "        Install Python 3.10+ and retry.\n"
  exit 1
fi

PY_VER="$("$PYTHON3_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJ="${PY_VER%%.*}"
PY_MIN="${PY_VER##*.}"
if (( PY_MAJ < 3 || (PY_MAJ == 3 && PY_MIN < 10) )); then
  printf "\n[ERROR] Python 3.10+ required (found %s).\n" "$PY_VER"
  printf "        Upgrade Python and retry.\n"
  exit 1
fi

if [[ "$CURRENT_DIR" != "$REPO_ROOT" ]]; then
  printf "\n[WARN] You are not in the mvar repo root.\n"
  printf "       Run: cd %s\n" "$REPO_ROOT"
fi

if [[ -d "$CURRENT_DIR/mvar" && -f "$CURRENT_DIR/mvar/setup.py" ]]; then
  printf "\n[WARN] You appear to be in a parent repo that contains mvar/.\n"
  printf "       Run: cd %s/mvar\n" "$CURRENT_DIR"
fi

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  printf "\n[WARN] No active virtual environment.\n"
  printf "       Recommended: source %s/bin/activate\n" "$EXPECTED_VENV"
else
  printf "  active venv: %s\n" "$VIRTUAL_ENV"
  if [[ "$VIRTUAL_ENV" != "$EXPECTED_VENV" ]]; then
    printf "\n[WARN] Active venv is not the local mvar venv.\n"
    printf "       Expected: %s\n" "$EXPECTED_VENV"
  fi
fi

if [[ ! -f "$REPO_ROOT/scripts/launch-gate.sh" ]]; then
  printf "\n[ERROR] launch-gate.sh not found under repo scripts/.\n"
  exit 1
fi

cat <<'TXT'

Golden path:
  cd <mvar-repo-root>
  python3 -m venv .venv
  source .venv/bin/activate
  python -m pip install -U pip setuptools wheel
  python -m pip install .
  bash scripts/quick-verify.sh
TXT
