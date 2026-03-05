#!/usr/bin/env bash
#
# MVAR Launch Gate — Pre-Launch Security Validation
#
# Runs comprehensive security validation before HackerNews launch:
# 1. Red-team gate tests (principal isolation, mechanism validation, token enforcement)
# 2. 50-vector attack corpus (all 9 categories)
# 3. Full test suite
#
# Exit code 0 = READY FOR LAUNCH
# Exit code 1 = BLOCKED (security issue found)

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$REPO_ROOT"

MVAR_GATE_VERBOSE="${MVAR_GATE_VERBOSE:-0}"

# Source-tree fallback for environments that do not install the package wheel.
if ! python3 - <<'PY' >/dev/null 2>&1
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("mvar_core") else 1)
PY
then
  ln -sfn mvar-core mvar_core
  export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
fi

# Select a single Python interpreter for all gate steps.
if [[ -n "${VIRTUAL_ENV:-}" ]] && [[ -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  echo "❌ PYTHON NOT FOUND"
  exit 1
fi

if "$PYTHON_BIN" -m pytest --version >/dev/null 2>&1; then
  PYTEST_CMD=("$PYTHON_BIN" -m pytest)
elif command -v pytest >/dev/null 2>&1; then
  echo "⚠️  Falling back to shell pytest: $(command -v pytest)"
  PYTEST_CMD=(pytest)
else
  echo "❌ PYTEST NOT FOUND"
  exit 1
fi

echo "================================"
echo "MVAR LAUNCH GATE — SECURITY VALIDATION"
echo "================================"
echo ""

# Step 0: Release metadata integrity
echo "0️⃣  Release Integrity"
echo "   - setup.py version matches mvar-core __version__"
echo ""
"$PYTHON_BIN" ./scripts/check_release_integrity.py || { echo "❌ RELEASE INTEGRITY FAILED"; exit 1; }
echo "✅ Release integrity: PASS"
echo ""

# Step 1: Red-Team Gate Tests
echo "1️⃣  Red-Team Gate Tests (7 tests)"
echo "   - Principal isolation"
echo "   - Override privilege escalation prevention"
echo "   - Execution token enforcement"
echo "   - Mechanism validation (no capability-only blocks)"
echo ""
"${PYTEST_CMD[@]}" -q tests/test_launch_redteam_gate.py || { echo "❌ RED-TEAM GATE FAILED"; exit 1; }
echo "✅ Red-team gate: PASS"
echo ""

# Step 1.5: Sink registration coverage
echo "1.5️⃣  Sink Registration Coverage Check"
echo "   - Verifies literal evaluate(tool, action) calls map to registered sinks"
echo ""
"$PYTHON_BIN" ./scripts/check_sink_registration_coverage.py || { echo "❌ SINK COVERAGE CHECK FAILED"; exit 1; }
echo "✅ Sink coverage: PASS"
echo ""

# Step 2: 50-Vector Attack Corpus
echo "2️⃣  50-Vector Attack Corpus (9 categories)"
echo "   - CVE-2026-25253 (6 vectors)"
echo "   - Environment variable attacks (5 vectors)"
echo "   - Encoding/obfuscation (8 vectors)"
echo "   - Shell manipulation (7 vectors)"
echo "   - Multi-stage attacks (6 vectors)"
echo "   - Taint laundering (5 vectors)"
echo "   - Template escape (5 vectors)"
echo "   - Credential theft (4 vectors)"
echo "   - Novel/zero-day (4 vectors)"
echo ""
ATTACK_LOG="$(mktemp)"
if [[ "$MVAR_GATE_VERBOSE" == "1" ]]; then
  "$PYTHON_BIN" -m demo.extreme_attack_suite_50 | tee "${ATTACK_LOG}"
else
  "$PYTHON_BIN" -m demo.extreme_attack_suite_50 | tee "${ATTACK_LOG}" >/dev/null
fi

grep -q "Total Attack Vectors Tested: 50" "${ATTACK_LOG}" || { echo "❌ ATTACK CORPUS FAILED: missing total vector count"; exit 1; }
grep -q "Attacks Blocked: 50" "${ATTACK_LOG}" || { echo "❌ ATTACK CORPUS FAILED: expected 50 blocked"; exit 1; }
grep -q "0 vectors blocked solely by capability deny-by-default" "${ATTACK_LOG}" || { echo "❌ ATTACK CORPUS FAILED: mechanism validation failed"; exit 1; }

echo ""
echo "Attack corpus summary:"
grep -E "^(Total Attack Vectors Tested|Attacks Blocked|Attacks Allowed|Success Rate|  • 0 vectors blocked solely by capability deny-by-default)" "${ATTACK_LOG}"
rm -f "${ATTACK_LOG}"
echo "✅ Attack corpus: 50/50 blocked"
echo ""

# Step 3: Full Test Suite
echo "3️⃣  Full Test Suite"
echo "   - Trust score, policy adjustment, and persistence"
echo "   - Red-team and adapter conformance"
echo "   - Benign corpus + hardening regressions"
echo ""
"${PYTEST_CMD[@]}" -q || { echo "❌ TEST SUITE FAILED"; exit 1; }
echo "✅ Full test suite: PASS"
echo ""

echo "================================"
echo "🎉 LAUNCH GATE: ALL SYSTEMS GO"
echo "================================"
echo ""
echo "✅ Security validation complete"
echo "✅ All launch-blocking issues resolved"
echo "✅ Ready for HackerNews launch"
echo ""

exit 0
