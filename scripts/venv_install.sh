#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PATH="${1:-/tmp/mvar-launch-final}"
USE_SYSTEM_SITE_PACKAGES="${USE_SYSTEM_SITE_PACKAGES:-0}"

if [[ "${USE_SYSTEM_SITE_PACKAGES}" == "1" ]]; then
  python3 -m venv --system-site-packages "${VENV_PATH}"
else
  python3 -m venv "${VENV_PATH}"
fi

source "${VENV_PATH}/bin/activate"

if ! python -m pip install --require-hashes -r "${REPO_ROOT}/requirements-ci.txt"; then
  echo "ERROR: Failed to install pinned dependencies from requirements-ci.txt."
  echo "      In restricted environments, pre-provision wheels from an internal mirror."
  exit 1
fi

ln -sfn "${REPO_ROOT}/mvar-core" "${REPO_ROOT}/mvar_core"
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

echo "Installed mvar into ${VENV_PATH}"
echo "Python: $(python -c 'import sys; print(sys.executable)')"
echo "PYTHONPATH: ${PYTHONPATH}"
