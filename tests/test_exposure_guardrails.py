"""Network exposure guardrail tests."""

import test_common  # noqa: F401
from exposure_guardrails import (
    check_network_exposure_guardrails,
    enforce_network_exposure_guardrails,
)


def test_default_env_has_no_public_bind_issue():
    result = check_network_exposure_guardrails({})
    assert result.ok is True
    assert result.issues == []


def test_ollama_public_bind_blocked_without_allow_or_auth():
    env = {"OLLAMA_HOST": "0.0.0.0:11434"}
    result = check_network_exposure_guardrails(env)
    assert result.ok is False
    assert any("Public bind detected" in issue for issue in result.issues)


def test_public_bind_allowed_with_auth_and_override():
    env = {
        "OLLAMA_HOST": "http://0.0.0.0:11434",
        "MVAR_ALLOW_PUBLIC_BIND": "1",
        "OLLAMA_API_KEY": "set",
    }
    result = check_network_exposure_guardrails(env)
    assert result.ok is True


def test_enforce_guardrails_raises_on_unsafe_public_bind():
    env = {
        "OPENCLAW_BIND_HOST": "0.0.0.0",
        "MVAR_ALLOW_PUBLIC_BIND": "0",
    }
    try:
        enforce_network_exposure_guardrails(env)
        assert False, "Expected RuntimeError for unsafe bind"
    except RuntimeError as exc:
        assert "Public bind detected" in str(exc)
