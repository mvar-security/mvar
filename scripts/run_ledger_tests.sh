#!/bin/bash
# MVAR Decision Ledger Test Runner
# Runs all 5 ledger tests in sequence using project venv

set -e  # Exit on first failure

echo ""
echo "================================================================================"
echo "MVAR Decision Ledger Test Suite"
echo "================================================================================"
echo ""

# Use Python 3.12 (Python 3.14 has editable install issues with PEP 660)
# Try multiple locations
if [ -f "/tmp/mvar-ledger-312/bin/python" ]; then
    PYTHON="/tmp/mvar-ledger-312/bin/python"
elif command -v python3.12 &> /dev/null; then
    PYTHON="python3.12"
elif command -v python3 &> /dev/null; then
    PYTHON="python3"
else
    echo "❌ ERROR: No compatible Python found"
    echo "Recommended: Python 3.12"
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

# Run tests with venv Python
$PYTHON tests/test_ledger_a_e2e_unblock.py
$PYTHON tests/test_ledger_b_ttl_expiry.py
$PYTHON tests/test_ledger_c_tamper_detection.py
$PYTHON tests/test_ledger_d_revocation.py
$PYTHON tests/test_ledger_e_attack_suite.py

echo ""
echo "================================================================================"
echo "✅ All 5 ledger tests PASSED"
echo "================================================================================"
echo ""
