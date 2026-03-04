#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PATH="${VENV_PATH:-$REPO_ROOT/.venv}"

log() { printf "\n[quick-verify] %s\n" "$*"; }
warn() { printf "\n[quick-verify][WARN] %s\n" "$*"; }
die() { printf "\n[quick-verify][ERROR] %s\n" "$*"; exit 1; }

if [[ ! -f "$REPO_ROOT/setup.py" ]] || [[ ! -f "$REPO_ROOT/scripts/launch-gate.sh" ]]; then
  die "Repo layout check failed at '$REPO_ROOT'. Run from a real mvar clone."
fi

if [[ -x "$VENV_PATH/bin/python" ]]; then
  PYTHON_BIN="$VENV_PATH/bin/python"
  log "Using existing venv python: $PYTHON_BIN"
else
  command -v python3 >/dev/null 2>&1 || die "python3 not found"
  log "Creating venv at $VENV_PATH"
  python3 -m venv "$VENV_PATH" || die "venv creation failed"
  PYTHON_BIN="$VENV_PATH/bin/python"
fi

if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
  warn "pip missing in venv; bootstrapping with ensurepip"
  "$PYTHON_BIN" -m ensurepip --upgrade || die "ensurepip failed"
fi

log "Upgrading packaging tools"
if ! "$PYTHON_BIN" -m pip install -U pip setuptools wheel; then
  warn "Could not upgrade pip/setuptools/wheel (likely restricted network). Continuing."
fi

log "Installing mvar package"
if ! "$PYTHON_BIN" -m pip install .; then
  warn "Build-isolated install failed; retrying without build isolation"
  "$PYTHON_BIN" -m pip install --no-build-isolation . || die "package install failed"
fi

cd "$REPO_ROOT"

if ! "$PYTHON_BIN" -m pytest --version >/dev/null 2>&1; then
  warn "pytest missing in venv; attempting install"
  if ! "$PYTHON_BIN" -m pip install pytest; then
    die "pytest install failed in venv. Provision pytest via network/internal mirror, then retry."
  fi
fi

PYTEST_CMD=("$PYTHON_BIN" -m pytest)

log "Running pytest"
"${PYTEST_CMD[@]}" -q

log "Running launch gate"
VENV_DIR="$(dirname "$(dirname "$PYTHON_BIN")")"
VIRTUAL_ENV="$VENV_DIR" PATH="$VENV_DIR/bin:$PATH" ./scripts/launch-gate.sh

log "Generating security scorecard"
"$PYTHON_BIN" scripts/generate_security_scorecard.py
"$PYTHON_BIN" scripts/update_status_md.py

log "Done. Validation + scorecard completed successfully."
