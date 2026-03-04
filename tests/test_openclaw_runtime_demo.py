"""Smoke test for concrete OpenClaw runtime integration demo."""

import subprocess
import sys
from pathlib import Path

import test_common  # noqa: F401


def test_openclaw_runtime_integration_demo_runs_with_expected_outcomes():
    repo_root = Path(__file__).resolve().parents[1]
    demo_path = repo_root / "demo" / "openclaw_runtime_integration_demo.py"

    proc = subprocess.run(
        [sys.executable, str(demo_path)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )

    stdout = proc.stdout
    assert "mvar_openclaw_runtime_demo" in stdout
    assert "total_dispatches=2" in stdout
    assert "executed_dispatches=1" in stdout
    assert "blocked_dispatches=1" in stdout
    assert "dispatch_1_outcome=allow" in stdout
    assert "dispatch_2_outcome=block" in stdout
