"""
Test S1501-01: Mission Control package import path fix.

Verifies that mvar.mission_control correctly exports MVARAdapter.
"""
import importlib
import pytest

# Skip if httpx not installed (Mission Control adapter requires it)
pytest.importorskip("httpx")


def test_mission_control_import_exports_adapter():
    """Verify mvar.mission_control exports MVARAdapter."""
    mod = importlib.import_module("mvar.mission_control")
    assert hasattr(mod, "MVARAdapter")
