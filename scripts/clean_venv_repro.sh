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
python -m pip install --upgrade pip

echo "--- Installing MVAR ---"
pip install .

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
