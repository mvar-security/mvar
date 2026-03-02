#!/usr/bin/env python3
"""Generate a machine-readable MVAR security scorecard."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
SCORECARD_PATH = REPORTS_DIR / "security_scorecard.json"


def _run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output


def _parse_attack_summary(output: str) -> tuple[int, int]:
    total_match = re.search(r"Total Attack Vectors Tested:\s*(\d+)", output)
    blocked_match = re.search(r"Attacks Blocked:\s*(\d+)", output)
    if not total_match or not blocked_match:
        raise RuntimeError("Unable to parse attack corpus summary")
    return int(total_match.group(1)), int(blocked_match.group(1))


def _parse_passed_count(output: str) -> int:
    match = re.search(r"(\d+) passed", output)
    return int(match.group(1)) if match else 0


def _git_commit() -> str:
    code, out = _run(["git", "rev-parse", "HEAD"])
    return out.strip() if code == 0 else "unknown"


def _git_version() -> str:
    init_path = REPO_ROOT / "mvar-core" / "__init__.py"
    if init_path.exists():
        text = init_path.read_text(encoding="utf-8")
        match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
        if match:
            return match.group(1)
    return "unknown"


def main() -> int:
    REPORTS_DIR.mkdir(exist_ok=True)

    attack_code, attack_output = _run(["python3", "-m", "demo.extreme_attack_suite_50"])
    if attack_code != 0:
        raise RuntimeError("Attack corpus execution failed")
    attack_total, attack_blocked = _parse_attack_summary(attack_output)

    benign_code, benign_output = _run(["pytest", "-q", "tests/test_benign_corpus.py"])
    benign_passed = _parse_passed_count(benign_output)
    benign_failures = 0 if benign_code == 0 else max(1, 200 - benign_passed)

    redteam_code, redteam_output = _run(["pytest", "-q", "tests/test_launch_redteam_gate.py"])
    redteam_passed = _parse_passed_count(redteam_output)

    scorecard = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": _git_version(),
        "commit": _git_commit(),
        "attack_corpus": {
            "total_vectors": attack_total,
            "blocked": attack_blocked,
            "block_rate": (attack_blocked / attack_total) if attack_total else 0.0,
        },
        "benign_corpus": {
            "total_vectors": 200,
            "passed": benign_passed,
            "false_blocks": benign_failures,
            "false_block_rate": (benign_failures / 200.0),
        },
        "redteam_gate": {
            "passed_tests": redteam_passed,
            "status": "pass" if redteam_code == 0 else "fail",
        },
    }

    SCORECARD_PATH.write_text(json.dumps(scorecard, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(scorecard, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
