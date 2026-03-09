#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
BASE_DIR="${REPO_ROOT}/artifacts/repro"
OUT_DIR="${BASE_DIR}/${RUN_ID}"
LATEST_LINK="${BASE_DIR}/latest"

mkdir -p "$OUT_DIR" "$BASE_DIR"

cd "$REPO_ROOT"

bash ./scripts/run-python.sh --version | tee "$OUT_DIR/python_version.txt"
bash ./scripts/run-python.sh - <<'PY' | tee "$OUT_DIR/runtime_context.txt"
import os
import platform
import sys
print(f"python_executable={sys.executable}")
print(f"python_version={platform.python_version()}")
print(f"platform={platform.platform()}")
print(f"cwd={os.getcwd()}")
PY

git rev-parse HEAD | tee "$OUT_DIR/git_commit.txt"

./scripts/launch-gate.sh | tee "$OUT_DIR/launch_gate.log"
bash ./scripts/run-python.sh ./scripts/check_sink_registration_coverage.py | tee "$OUT_DIR/sink_coverage.log"
bash ./scripts/run-python.sh ./scripts/emit_validation_summary.py "$OUT_DIR/launch_gate.log" "$OUT_DIR/validation_summary.json" \
  | tee "$OUT_DIR/validation_summary.pretty.json"

bash ./scripts/run-python.sh - <<'PY' "$OUT_DIR/validation_summary.json"
import json
import sys
from pathlib import Path
summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not summary.get("proof_pack_ready"):
    raise SystemExit("proof pack not ready: launch gate summary did not satisfy strict checks")
print("proof_pack_ready=true")
PY

if command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=(sha256sum)
else
  echo "No SHA-256 command found (need shasum or sha256sum)" >&2
  exit 1
fi

(cd "$OUT_DIR" && \
  "${HASH_CMD[@]}" launch_gate.log sink_coverage.log validation_summary.json validation_summary.pretty.json \
    python_version.txt runtime_context.txt git_commit.txt > checksums.sha256)

ln -sfn "$OUT_DIR" "$LATEST_LINK"

printf "\nReproducibility artifact pack written to %s\n" "$OUT_DIR"
printf "Latest link updated: %s -> %s\n" "$LATEST_LINK" "$OUT_DIR"
