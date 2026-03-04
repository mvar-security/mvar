#!/usr/bin/env bash
set -euo pipefail

echo "=================================="
echo "MVAR Reproducibility Test"
echo "=================================="
echo ""

echo "--- Environment Info ---"
echo "Python version: $(python3 --version)"
echo "Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"
echo ""

echo "--- Creating fresh virtual environment ---"
python3 -m venv .repro_venv
source .repro_venv/bin/activate

echo "--- Upgrading pip ---"
if ! python -m pip install --upgrade pip setuptools wheel; then
  echo "WARN: Could not upgrade pip/setuptools/wheel (likely offline/restricted index)."
  echo "      Continuing with existing packaging tools."
fi

# Python 3.14+ venvs may not include setuptools by default in offline environments.
if ! python - <<'PY' >/dev/null 2>&1
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("setuptools") else 1)
PY
then
  echo "WARN: setuptools missing in isolated repro venv."
  echo "      Recreating repro venv with --system-site-packages fallback."
  deactivate || true
  rm -rf .repro_venv
  python3 -m venv --system-site-packages .repro_venv
  source .repro_venv/bin/activate
fi

echo "--- Installing MVAR ---"
if ! python -m pip install .; then
  echo "WARN: Build-isolated install failed; retrying without build isolation."
  if ! python -m pip install --no-build-isolation .; then
    echo "❌ ERROR: Could not install MVAR in repro venv."
    echo "   In restricted environments, pre-provision packaging tools from an internal mirror."
    exit 1
  fi
fi

echo ""
echo "--- Import Verification ---"
python - <<EOF
import mvar_core
print("MVAR import: OK")
print("MVAR version:", mvar_core.__version__)
EOF
echo ""

echo "--- Running 12-vector validation suite ---"
python -m demo.comprehensive_attack_suite
echo ""

echo "--- Running 50-vector validation suite ---"
python -m demo.extreme_attack_suite_50
echo ""

echo "=================================="
echo "REPRO PASS: Suites executed successfully"
echo "Note: Results reflect this corpus + configuration"
echo "=================================="
