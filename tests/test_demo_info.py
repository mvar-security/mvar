"""Sanity checks for demo info/doctor commands."""

import importlib.util
from pathlib import Path

import test_common  # noqa: F401

INFO_MODULE_PATH = Path(__file__).resolve().parents[1] / "demo" / "info.py"


def _load_info_module():
    spec = importlib.util.spec_from_file_location("mvar_demo_info_local", INFO_MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_info_module_reports_current_version(capsys):
    info = _load_info_module()
    info.main()
    captured = capsys.readouterr().out
    assert f"Version: {info.MVAR_VERSION}" in captured


def test_doctor_blocks_unsafe_public_bind(monkeypatch):
    info = _load_info_module()
    monkeypatch.setenv("OLLAMA_HOST", "0.0.0.0:11434")
    monkeypatch.delenv("MVAR_ALLOW_PUBLIC_BIND", raising=False)
    monkeypatch.delenv("MVAR_GATEWAY_AUTH_TOKEN", raising=False)

    result = info._doctor()  # pylint: disable=protected-access
    assert result == 1


def test_doctor_allows_public_bind_with_explicit_auth(monkeypatch):
    info = _load_info_module()
    monkeypatch.setenv("OPENCLAW_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("MVAR_ALLOW_PUBLIC_BIND", "1")
    monkeypatch.setenv("MVAR_GATEWAY_AUTH_TOKEN", "test_token")

    result = info._doctor()  # pylint: disable=protected-access
    assert result == 0
