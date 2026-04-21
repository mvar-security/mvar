"""
Test I1501-02: Remove secret leakage from installer/logs.

Verifies that secrets are not printed to stdout or debug logs.
"""
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from io import StringIO


def test_install_hook_does_not_print_secret_values():
    """Verify installer code doesn't print actual secret values."""
    # Read the installer code
    with open('mvar/adapters/claude_code.py', 'r') as f:
        code = f.read()

    # Verify the code does NOT print secret values
    # Old code had: print(f"      ✅ {qseal_secret[:16]}... (32 bytes)")
    assert 'qseal_secret[:16]' not in code, "Code leaks QSEAL_SECRET prefix"
    assert 'qseal_secret[:' not in code, "Code leaks partial QSEAL_SECRET"

    # Old code had: print(f"      ✅ API key: {mc_api_key[:8]}...")
    assert 'mc_api_key[:8]' not in code, "Code leaks MC_API_KEY prefix"
    assert 'mc_api_key[:' not in code, "Code leaks partial MC_API_KEY"

    # Verify the NEW safe code is present
    assert 'QSEAL_SECRET generated' in code or 'QSEAL_SECRET configured' in code
    assert 'MC_API_KEY configured' in code


def test_hook_debug_disabled_by_default(monkeypatch, tmp_path):
    """Verify hook debug logging is disabled by default."""
    # Ensure MVAR_HOOK_DEBUG is not set
    monkeypatch.delenv("MVAR_HOOK_DEBUG", raising=False)

    # Import after env is cleared
    import importlib
    import mvar.hooks.governor_hook
    importlib.reload(mvar.hooks.governor_hook)

    # Verify DEBUG_ENABLED is False
    assert mvar.hooks.governor_hook.DEBUG_ENABLED is False


def test_hook_debug_enabled_with_flag(monkeypatch):
    """Verify hook debug logging can be enabled with env var."""
    # Set MVAR_HOOK_DEBUG=1
    monkeypatch.setenv("MVAR_HOOK_DEBUG", "1")

    # Import after env is set
    import importlib
    import mvar.hooks.governor_hook
    importlib.reload(mvar.hooks.governor_hook)

    # Verify DEBUG_ENABLED is True
    assert mvar.hooks.governor_hook.DEBUG_ENABLED is True
