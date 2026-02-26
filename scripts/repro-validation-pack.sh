#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
OUT_DIR="${REPO_ROOT}/artifacts/repro/latest"

mkdir -p "$OUT_DIR"

cd "$REPO_ROOT"

python3 --version | tee "$OUT_DIR/python_version.txt"

./scripts/launch-gate.sh | tee "$OUT_DIR/launch_gate.log"
python3 ./scripts/check_sink_registration_coverage.py | tee "$OUT_DIR/sink_coverage.log"
python3 ./scripts/emit_validation_summary.py "$OUT_DIR/launch_gate.log" "$OUT_DIR/validation_summary.json" \
  | tee "$OUT_DIR/validation_summary.pretty.json"

printf "\nReproducibility artifact pack written to %s\n" "$OUT_DIR"
