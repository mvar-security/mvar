"""Identity continuity gate: the governor consumes trust_established.

A request whose prompt provenance carries an `identity_context` block is opted
into recognition enforcement: an agent whose verified continuity is not
established never receives an automatic allow — the SAME action that allows
for an established agent elevates to step-up for a stranger. Requests without
identity_context are unaffected (fully backward compatible), and established
continuity never overrides a block (a gate, never a bypass).
"""

import os

import pytest

from mvar.governor import ExecutionGovernor

ESTABLISHED = {
    "agent_id": "agent-known",
    "continuity_verified": True,
    "session_count": 5,
    "trust_established": True,
}
STRANGER = {
    "agent_id": "agent-new",
    "continuity_verified": False,
    "session_count": 0,
    "trust_established": False,
}


def _request(identity_context=None, sink_type="tool.custom", target="summarize the report"):
    provenance = {
        "source": "user_request",
        "taint_level": "trusted",
        "source_chain": ["user_request", "tool_call"],
    }
    if identity_context is not None:
        provenance["identity_context"] = dict(identity_context)
    return {
        "sink_type": sink_type,
        "target": target,
        "arguments": {},
        "prompt_provenance": provenance,
    }


@pytest.fixture()
def governor():
    # Governor construction writes profile env overrides; restore the
    # environment afterwards (suite convention, see test_api_contracts.py).
    original_env = os.environ.copy()
    try:
        # Signing needs a QSEAL secret; without one the fail-closed
        # allow-path blocks (by design), which is not what these tests
        # assert. Suite convention: tests set their own test secret
        # (see test_witness_verifier.py). setdefault keeps a real one.
        os.environ.setdefault("QSEAL_SECRET", "unit-test-secret")
        yield ExecutionGovernor(policy_profile="dev_balanced")
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_same_action_allows_established_and_gates_stranger(governor):
    known = governor.evaluate(_request(ESTABLISHED))
    stranger = governor.evaluate(_request(STRANGER))

    assert known.decision == "allow"
    assert known.reason_code == "POLICY_ALLOW"

    assert stranger.decision == "annotate"
    assert stranger.reason_code == "CONTINUITY_NOT_ESTABLISHED"
    assert stranger.enforcement_action == "block_until_approved"
    assert "identity_continuity=not_established" in stranger.evaluation_trace


def test_no_identity_context_is_unaffected(governor):
    baseline = governor.evaluate(_request(None))
    assert baseline.decision == "allow"
    assert not any(
        str(entry).startswith("identity_continuity=") for entry in baseline.evaluation_trace
    ), "requests without identity_context must not enter the gate"


def test_claimed_trust_without_verification_is_not_established(governor):
    tricked = governor.evaluate(
        _request({"trust_established": True, "continuity_verified": False})
    )
    assert tricked.decision == "annotate"
    assert tricked.reason_code == "CONTINUITY_NOT_ESTABLISHED"


def test_established_continuity_never_overrides_a_block(governor):
    request = _request(ESTABLISHED, sink_type="shell.exec", target="echo hello")
    request["prompt_provenance"]["taint_level"] = "untrusted"
    request["prompt_provenance"]["source"] = "external_document"
    decision = governor.evaluate(request)
    assert decision.decision == "block", "recognition is a gate, never a bypass"


def test_established_trace_is_recorded_on_allow(governor):
    known = governor.evaluate(_request(ESTABLISHED))
    assert "identity_continuity=established" in known.evaluation_trace
