"""Regression tests for proof-pack summary emission."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def _run_emit_script(repo_root: Path, log_path: Path, out_path: Path) -> dict:
    script = repo_root / "scripts" / "emit_validation_summary.py"
    subprocess.check_call(
        [sys.executable, str(script), str(log_path), str(out_path)],
        cwd=repo_root,
    )
    return json.loads(out_path.read_text(encoding="utf-8"))


def test_emit_validation_summary_marks_ready_for_valid_launch_gate(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    log_path = tmp_path / "launch_gate.log"
    out_path = tmp_path / "summary.json"
    log_path.write_text(
        "\n".join(
            [
                ".......",
                "7 passed in 0.42s",
                "✅ Red-team gate: PASS",
                "Total Attack Vectors Tested: 50",
                "Attacks Blocked: 50",
                "Attacks Allowed: 0",
                "279 passed in 11.20s",
                "🎉 LAUNCH GATE: ALL SYSTEMS GO",
            ]
        ),
        encoding="utf-8",
    )

    summary = _run_emit_script(repo_root, log_path, out_path)
    assert summary["schema_version"] == "proof_pack_summary.v1"
    assert summary["redteam_passed"] == 7
    assert summary["attack_total"] == 50
    assert summary["attack_blocked"] == 50
    assert summary["attack_allowed"] == 0
    assert summary["full_suite_passed"] == 279
    assert summary["all_systems_go"] is True
    assert summary["proof_pack_ready"] is True


def test_emit_validation_summary_marks_not_ready_when_gate_incomplete(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    log_path = tmp_path / "launch_gate.log"
    out_path = tmp_path / "summary.json"
    log_path.write_text(
        "\n".join(
            [
                "7 passed in 0.42s",
                "✅ Red-team gate: PASS",
                "Total Attack Vectors Tested: 50",
                "Attacks Blocked: 49",
                "Attacks Allowed: 1",
                "279 passed in 11.20s",
            ]
        ),
        encoding="utf-8",
    )

    summary = _run_emit_script(repo_root, log_path, out_path)
    assert summary["all_systems_go"] is False
    assert summary["proof_pack_ready"] is False
