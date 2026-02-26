#!/usr/bin/env bash
set -euo pipefail

VENV_PATH="${1:-/tmp/mvar-launch-final}"
USE_SYSTEM_SITE_PACKAGES="${USE_SYSTEM_SITE_PACKAGES:-0}"

if [[ "${USE_SYSTEM_SITE_PACKAGES}" == "1" ]]; then
  python3 -m venv --system-site-packages "${VENV_PATH}"
else
  python3 -m venv "${VENV_PATH}"
fi

source "${VENV_PATH}/bin/activate"

if ! python -m pip install -U pip setuptools wheel; then
  echo "WARN: Could not upgrade pip/setuptools/wheel (likely offline/restricted index)."
  echo "      Continuing with existing packaging tools."
fi

if ! python -m pip install --no-build-isolation .; then
  echo "ERROR: Install failed. In restricted environments, pre-provision pip/setuptools/wheel from your internal mirror."
  exit 1
fi

echo "Installed mvar into ${VENV_PATH}"
echo "Python: $(python -c 'import sys; print(sys.executable)')"
echo "CLI path: $(command -v mvar-demo)"
