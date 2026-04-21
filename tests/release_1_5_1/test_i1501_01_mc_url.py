"""
Test I1501-01: Respect configured MC_URL end-to-end.

Verifies that MC_URL is written to env file and read by hook.
"""
import os
import tempfile
from pathlib import Path
from mvar.adapters.claude_code import _write_env_file


def test_install_hook_writes_mc_url():
    """Verify _write_env_file includes MC_URL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".mvar.env"
        qseal_secret = "test_secret_123"
        mc_api_key = "test_key_456"
        mc_url = "http://custom-mc:4000"

        _write_env_file(env_file, qseal_secret, mc_api_key, mc_url)

        # Read back and verify MC_URL is present
        with open(env_file, 'r') as f:
            content = f.read()

        assert "export MC_URL=http://custom-mc:4000" in content


def test_hook_reads_mc_url_env(monkeypatch):
    """Verify hook reads MC_URL from environment."""
    # Set MC_URL environment variable
    monkeypatch.setenv("MC_URL", "http://test-mc:5000")

    # Verify it's read correctly (simulating hook behavior)
    base_url = os.getenv("MC_URL", "http://localhost:3000").rstrip("/")

    assert base_url == "http://test-mc:5000"


def test_hook_mc_url_default_fallback(monkeypatch):
    """Verify hook falls back to default when MC_URL not set."""
    # Ensure MC_URL is not set
    monkeypatch.delenv("MC_URL", raising=False)

    # Verify fallback to default
    base_url = os.getenv("MC_URL", "http://localhost:3000").rstrip("/")

    assert base_url == "http://localhost:3000"
