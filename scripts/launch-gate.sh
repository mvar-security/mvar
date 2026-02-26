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

echo "================================"
echo "MVAR LAUNCH GATE — SECURITY VALIDATION"
echo "================================"
echo ""

# Step 1: Red-Team Gate Tests
echo "1️⃣  Red-Team Gate Tests (5 tests)"
echo "   - Principal isolation"
echo "   - Override privilege escalation prevention"
echo "   - Execution token enforcement"
echo "   - Mechanism validation (no capability-only blocks)"
echo ""
pytest -q tests/test_launch_redteam_gate.py || { echo "❌ RED-TEAM GATE FAILED"; exit 1; }
echo "✅ Red-team gate: PASS"
echo ""

# Step 1.5: Sink registration coverage
echo "1.5️⃣  Sink Registration Coverage Check"
echo "   - Verifies literal evaluate(tool, action) calls map to registered sinks"
echo ""
python3 ./scripts/check_sink_registration_coverage.py || { echo "❌ SINK COVERAGE CHECK FAILED"; exit 1; }
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
  python3 -m demo.extreme_attack_suite_50 | tee "${ATTACK_LOG}"
else
  python3 -m demo.extreme_attack_suite_50 | tee "${ATTACK_LOG}" >/dev/null
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
echo "   - Trust score computation (6 tests)"
echo "   - Policy adjustment (4 tests)"
echo "   - State persistence (5 tests)"
echo "   - Red-team gate (5 tests)"
echo "   - First-party adapter wrappers (6 tests)"
echo ""
pytest -q || { echo "❌ TEST SUITE FAILED"; exit 1; }
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
