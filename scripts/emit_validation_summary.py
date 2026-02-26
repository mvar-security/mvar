#!/usr/bin/env python3
"""Emit deterministic JSON summary from launch-gate output."""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PATTERNS = {
    "redteam_passed": re.compile(r"(\d+) passed in .*Red-team gate", re.DOTALL),
    "attack_total": re.compile(r"Total Attack Vectors Tested:\s*(\d+)"),
    "attack_blocked": re.compile(r"Attacks Blocked:\s*(\d+)"),
    "attack_allowed": re.compile(r"Attacks Allowed:\s*(\d+)"),
    "all_pass_counts": re.compile(r"(\d+) passed in"),
}


def _extract_int(pattern: re.Pattern[str], text: str) -> int | None:
    m = pattern.search(text)
    return int(m.group(1)) if m else None


def _extract_full_suite_passed(text: str) -> int | None:
    counts = [int(m.group(1)) for m in PATTERNS["all_pass_counts"].finditer(text)]
    return max(counts) if counts else None


def _git_rev(repo_root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(repo_root), "rev-parse", "HEAD"], text=True).strip()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: emit_validation_summary.py <launch_gate_log> <output_json>", file=sys.stderr)
        return 2

    log_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    repo_root = Path(__file__).resolve().parents[1]

    text = log_path.read_text(encoding="utf-8")

    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_rev(repo_root),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "redteam_passed": _extract_int(PATTERNS["redteam_passed"], text),
        "attack_total": _extract_int(PATTERNS["attack_total"], text),
        "attack_blocked": _extract_int(PATTERNS["attack_blocked"], text),
        "attack_allowed": _extract_int(PATTERNS["attack_allowed"], text),
        "full_suite_passed": _extract_full_suite_passed(text),
        "all_systems_go": "LAUNCH GATE: ALL SYSTEMS GO" in text,
        "source_log": os.fspath(log_path),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
