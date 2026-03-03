#!/bin/bash
# MVAR Decision Ledger Test Runner
# Runs all 5 ledger tests in sequence using project venv

set -e  # Exit on first failure

echo ""
echo "================================================================================"
echo "MVAR Decision Ledger Test Suite"
echo "================================================================================"
echo ""

# Prefer active venv python if present; otherwise fall back to system python.
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
    PYTHON="${VIRTUAL_ENV}/bin/python"
elif command -v python3 &> /dev/null; then
    PYTHON="python3"
else
    echo "❌ ERROR: No compatible Python found"
    exit 1
fi

# Enable ledger + QSEAL
export MVAR_ENABLE_LEDGER=1
export QSEAL_SECRET="test_secret_key_for_local_validation_only"

echo "Test environment:"
echo "  Python: $PYTHON ($($PYTHON --version))"
echo "  MVAR_ENABLE_LEDGER: $MVAR_ENABLE_LEDGER"
echo "  QSEAL_SECRET: ${QSEAL_SECRET:0:16}..."
echo ""

# Prefer pytest from current shell/venv; fall back to python -m pytest.
if command -v pytest &> /dev/null; then
    PYTEST_CMD=(pytest)
elif $PYTHON -m pytest --version &> /dev/null; then
    PYTEST_CMD=($PYTHON -m pytest)
else
    echo "❌ ERROR: pytest not found for the selected environment"
    echo "Install pytest (for example: python -m pip install pytest)"
    exit 1
fi

# Run via pytest so path setup and fixtures are consistent with CI/local gates.
"${PYTEST_CMD[@]}" -q \
  tests/test_ledger_a_e2e_unblock.py \
  tests/test_ledger_b_ttl_expiry.py \
  tests/test_ledger_c_tamper_detection.py \
  tests/test_ledger_d_revocation.py \
  tests/test_ledger_e_attack_suite.py

echo ""
echo "================================================================================"
echo "✅ All 5 ledger tests PASSED"
echo "================================================================================"
echo ""
