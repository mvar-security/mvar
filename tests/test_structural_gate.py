"""Governor-side structural gate: the governor consumes reachable_sinks.

Mirrors test_identity_continuity_gate.py exactly — module-scenario dicts, a
_request() builder, the dev_balanced governor fixture that snapshots/restores
os.environ and setdefaults QSEAL_SECRET, membership asserts on evaluation_trace,
sentence-shaped test names.

A request whose prompt provenance carries a `structural` block is opted into
derived-capability enforcement: code wired to reach a sensitive sink the
declared sink never authorized elevates an allow to step-up. Requests without
the block are unaffected; a structural finding never overrides a block.
"""

import os

import pytest

from mvar.governor import ExecutionGovernor

# A declared-read-only tool whose implementation reaches an HTTP egress sink.
DECEPTIVE_READER = {
    "reachable_sinks": {
        "net.http": {"sink": "requests.post", "path": ["read_report", "_exfiltrate", "requests.post"]}
    },
    "dynamic_dispatch": False,
}
# A legitimate reader that reaches nothing sensitive.
CLEAN_READER = {"reachable_sinks": {}, "dynamic_dispatch": False}


def _request(structural=None, sink_type="filesystem.read", target="notes.txt"):
    provenance = {
        "source": "user_request",
        "taint_level": "trusted",
        "source_chain": ["user_request", "tool_call"],
    }
    if structural is not None:
        provenance["structural"] = dict(structural)
    return {
        "sink_type": sink_type,
        "target": target,
        "arguments": {},
        "prompt_provenance": provenance,
    }


@pytest.fixture()
def governor():
    original_env = os.environ.copy()
    try:
        os.environ.setdefault("QSEAL_SECRET", "unit-test-secret")
        yield ExecutionGovernor(policy_profile="dev_balanced")
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_declared_read_only_reaching_network_is_stepped_up(governor):
    decision = governor.evaluate(_request(DECEPTIVE_READER))
    assert decision.decision == "annotate"
    assert decision.reason_code == "STRUCTURAL_SINK_REACHABLE"
    assert decision.enforcement_action == "block_until_approved"
    assert "structural_reachable=net.http" in decision.evaluation_trace
    assert any(
        "read_report→_exfiltrate→requests.post" in str(e) for e in decision.evaluation_trace
    )


def test_clean_reader_with_structural_block_is_allowed(governor):
    # Discrimination: a reader that reaches no sensitive sink is ALLOWED even
    # though it carries a structural block — the gate must not blanket-block
    # anything that opts into the axis. (Decision, not telemetry, is asserted:
    # neutering the gate must NOT flip this test, only the step-up test.)
    decision = governor.evaluate(_request(CLEAN_READER))
    assert decision.decision == "allow"
    assert decision.reason_code == "POLICY_ALLOW"


def test_no_structural_block_is_unaffected(governor):
    decision = governor.evaluate(_request(None))
    assert decision.decision == "allow"
    assert not any(
        str(e).startswith("structural_reachable=") for e in decision.evaluation_trace
    ), "requests without a structural block must not enter the gate"


def test_declared_poster_reaching_network_is_authorized(governor):
    # An http.request sink is EXPECTED to reach net.http — not a mismatch.
    decision = governor.evaluate(
        _request(DECEPTIVE_READER, sink_type="http.request", target="https://api.example.com/x")
    )
    assert decision.decision == "allow"


def test_structural_finding_never_overrides_a_block(governor):
    request = _request(DECEPTIVE_READER, sink_type="shell.exec", target="echo hi")
    request["prompt_provenance"]["taint_level"] = "untrusted"
    request["prompt_provenance"]["source"] = "external_document"
    decision = governor.evaluate(request)
    assert decision.decision == "block", "structural is a gate, never a bypass"


def test_dynamic_dispatch_is_recorded(governor):
    ctx = {"reachable_sinks": {}, "dynamic_dispatch": True}
    decision = governor.evaluate(_request(ctx))
    assert "structural_dynamic_dispatch=cannot_bound_reachable_sinks" in decision.evaluation_trace
