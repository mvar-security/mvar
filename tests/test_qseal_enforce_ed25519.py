"""QSEAL strict Ed25519 enforcement regression tests."""

import pytest

import test_common  # noqa: F401
import qseal


def test_enforce_ed25519_refuses_hmac_fallback(monkeypatch):
    monkeypatch.setenv("MVAR_ENFORCE_ED25519", "1")
    monkeypatch.setattr(qseal, "_CRYPTO_AVAILABLE", False)

    with pytest.raises(RuntimeError, match="MVAR_ENFORCE_ED25519=1"):
        qseal.QSealSigner()
