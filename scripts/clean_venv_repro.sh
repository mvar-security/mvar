#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

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

echo "--- Installing pinned dependencies ---"
if ! python -m pip install --require-hashes -r "${REPO_ROOT}/requirements-ci.txt"; then
  echo "❌ ERROR: Could not install pinned dependencies."
  echo "   In restricted environments, pre-provision wheels from an internal mirror."
  exit 1
fi

ln -sfn "${REPO_ROOT}/mvar-core" "${REPO_ROOT}/mvar_core"
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

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
