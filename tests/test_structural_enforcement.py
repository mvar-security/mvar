"""Structural-dependency-aware enforcement — the ratification tests.

Spec: docs/specs/STRUCTURAL_ENFORCEMENT_SPEC.md (bridge). Two load-bearing
guarantees, both proven by injection:

  1. The positive/red-if-removed test — a tool DECLARED read-only whose body
     transitively reaches requests.post is blocked BECAUSE the structural graph
     found the multi-hop network sink; disable the analyzer and the SAME
     deceptive tool runs unmediated (the forgery slips past → RED).
  2. The false-positive discrimination test — a legitimate read-only tool that
     shares a structural neighborhood with a network sink but never calls it is
     ALLOWED. This is what separates a real feature from one that blocks
     everything connected to anything sensitive.

House style mirrors test_protect.py (fake runtime → deterministic ALLOW so the
structural axis is what's under test) and test_identity_continuity_gate.py
(governor-level gate assertions on evaluation_trace).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

import mvar
from mvar import ExecutionBlocked, protect, structural
from mvar_core.profiles import SecurityProfile

# House convention (see test_common.py, test_egress_ssrf_denylist.py): sys.path
# insert + direct import rather than package-relative — tests/ is not a package.
_FIXTURES = Path(__file__).resolve().parent / "structural_fixtures"
if str(_FIXTURES) not in sys.path:
    sys.path.insert(0, str(_FIXTURES))
import deceptive_tools  # noqa: E402


class _FakeDecision:
    def __init__(self, outcome: str = "allow", reason: str = "allowed") -> None:
        self.decision_id = "decision-test"
        self._outcome = outcome
        self._reason = reason
        self.execution_token = {"token": "unit-test-token"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self._outcome,
            "reason": self._reason,
            "sink": {"tool": "t", "action": "read", "risk": "low", "rationale": "x"},
            "provenance": {"node_id": "p1", "source": "u", "integrity": "trusted",
                           "confidentiality": "public", "taint_tags": []},
            "evaluation_trace": ["unit-test-trace"],
            "timestamp": "2026-07-08T00:00:00Z",
            "qseal_signature": {"algo": "ed25519", "sig": "unit-test"},
        }


def _install_allow_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the flat pipeline to ALLOW so only the structural axis decides."""
    class _FakeAdapter:
        def __init__(self, policy: object, graph: object) -> None:
            pass

        def create_user_provenance(self, text: str) -> str:
            return "trusted-node"

        def create_untrusted_provenance(self, text: str, source: str = "external_doc") -> str:
            return "untrusted-node"

        def evaluate(self, *a: Any, **k: Any) -> _FakeDecision:
            return _FakeDecision()

        def authorize_execution(self, *a: Any, **k: Any) -> _FakeDecision:
            return _FakeDecision()

    def _fake_runtime(profile: SecurityProfile, **kwargs: Any) -> tuple[object, object, object]:
        return object(), object(), object()

    monkeypatch.setattr(mvar, "MVARExecutionAdapter", _FakeAdapter)
    monkeypatch.setattr(mvar, "create_default_runtime", _fake_runtime)


@pytest.fixture(autouse=True)
def _fresh_baselines():
    structural.reset_baselines()
    yield
    structural.reset_baselines()


# --------------------------------------------------------------------------
# 1. Positive test — the graph blocks what flat classification misses
# --------------------------------------------------------------------------

def test_multi_hop_reachable_sink_is_blocked_when_flat_would_allow(monkeypatch):
    _install_allow_runtime(monkeypatch)
    # Declared read-only (action="read"); flat pipeline is forced to ALLOW.
    protected = protect(deceptive_tools.read_report, tool_name="read_report", action="read")

    with pytest.raises(ExecutionBlocked) as exc:
        protected("/etc/passwd")

    record = exc.value.decision
    assert record["reason"] == structural.REASON_SINK_REACHABLE
    rules = record["policy"]["rulesEvaluated"]
    assert "structural_reachable=net.http" in rules
    assert any("read_report→_exfiltrate→requests.post" in r for r in rules), rules
    assert record["structural"]["classes"] == ["net.http"]


# --------------------------------------------------------------------------
# 2. Load-bearing / red-if-removed — disable the analyzer, forgery slips past
# --------------------------------------------------------------------------

def test_structural_analyzer_is_the_load_bearing_guard(monkeypatch):
    _install_allow_runtime(monkeypatch)

    # FIRST: with the analyzer live, the deceptive tool is blocked.
    protected = protect(deceptive_tools.read_report, tool_name="read_report", action="read")
    with pytest.raises(ExecutionBlocked):
        protected("/etc/passwd")

    # NOW disable ONLY the structural derivation — analyzer yields no context,
    # exactly as if the package were absent (fail-closed-to-flat path).
    structural.reset_baselines()
    monkeypatch.setattr(
        mvar._structural, "derive_structural_context", lambda *a, **k: None
    )

    protected_blind = protect(deceptive_tools.read_report, tool_name="read_report", action="read")
    # The SAME deceptive tool now runs unmediated: MVAR does NOT block it, so
    # control reaches the tool body and the hidden requests.post fires. We must
    # not make a real network call in a unit test, so stub the sink to a marker
    # and prove the body executed (i.e. was NOT blocked by MVAR).
    reached = {}

    def _fake_exfiltrate(data):
        reached["egress"] = True
        return "sent"

    monkeypatch.setattr(deceptive_tools, "_exfiltrate", _fake_exfiltrate)
    result = protected_blind("/etc/passwd")
    assert reached.get("egress") is True and result == "sent", (
        "RED-IF-REMOVED: without the structural analyzer, MVAR did not block the "
        "network-reaching tool — its body executed and reached the egress sink. "
        "The structural analyzer WAS the guard."
    )


# --------------------------------------------------------------------------
# 3. False-positive discrimination — legitimate neighbor is ALLOWED
# --------------------------------------------------------------------------

def test_legitimate_read_only_neighbor_of_a_sink_is_allowed(monkeypatch):
    _install_allow_runtime(monkeypatch)
    # summarize_report lives in the SAME module as _exfiltrate/requests but
    # never calls the network helper. It must run, not block.
    protected = protect(deceptive_tools.summarize_report, tool_name="summarize_report", action="read")
    out = protected("/etc/hostname")
    assert out is not None, (
        "discrimination failure: a legitimate read-only tool that merely shares "
        "a module with a sink was blocked — the feature would be unusable."
    )


# --------------------------------------------------------------------------
# 4. Escalate-only — a structural finding never overrides a block
# --------------------------------------------------------------------------

def test_structural_finding_never_overrides_a_block(monkeypatch):
    _install_allow_runtime(monkeypatch)
    monkeypatch.setattr(
        mvar, "create_default_runtime",
        lambda profile, **k: (_ for _ in ()).throw(AssertionError("unused")),
        raising=True,
    )
    # Re-install a BLOCK-returning runtime; structural must not turn it into allow.
    class _BlockDecision(_FakeDecision):
        def to_dict(self):
            d = super().to_dict()
            d["outcome"] = "block"
            d["reason"] = "TAINT_BLOCK"
            return d

    class _BlockAdapter:
        def __init__(self, *a, **k): pass
        def create_user_provenance(self, t): return "n"
        def create_untrusted_provenance(self, t, source="external_doc"): return "n"
        def evaluate(self, *a, **k): return _BlockDecision()
        def authorize_execution(self, *a, **k): return _BlockDecision()

    monkeypatch.setattr(mvar, "MVARExecutionAdapter", _BlockAdapter)
    monkeypatch.setattr(mvar, "create_default_runtime", lambda profile, **k: (object(), object(), object()))

    protected = protect(deceptive_tools.read_report, tool_name="read_report", action="read")
    with pytest.raises(ExecutionBlocked) as exc:
        protected("/etc/passwd")
    # The block is the flat taint block, NOT re-labeled by structural.
    assert exc.value.decision["reason"] == "TAINT_BLOCK"


# --------------------------------------------------------------------------
# 5. Capability drift — reachable-sink set widening is re-gated (step-up)
# --------------------------------------------------------------------------

def test_capability_drift_widening_is_stepped_up():
    # First derivation of an identity establishes the baseline...
    ctx1 = {"tool": "acme.formatter", "reachable_sinks": {}, "dynamic_dispatch": False}
    structural.reset_baselines()
    # prime baseline via the public deriver by faking analyzer output:
    structural._baseline_registry["acme.formatter"] = frozenset()
    # ...now the same tool's code has gained a network sink.
    ctx2 = {
        "tool": "acme.formatter",
        "reachable_sinks": {"net.http": {"sink": "requests.post", "path": ["fmt", "requests.post"]}},
        "dynamic_dispatch": False,
        "capability_drift": True,
        "new_sinks": ["net.http"],
    }
    # Declared as a formatter authorizing nothing → widening to net.http fires.
    finding = structural.evaluate_structural(ctx2, authorized_classes=frozenset())
    assert finding is not None and finding["code"] == structural.REASON_SINK_REACHABLE
    _ = ctx1  # documents the before-state


# --------------------------------------------------------------------------
# 6. Dynamic dispatch is surfaced, not silently cleared
# --------------------------------------------------------------------------

def test_dynamic_dispatch_is_flagged():
    ctx = {
        "tool": "x.y",
        "reachable_sinks": {},
        "dynamic_dispatch": True,
    }
    lines = structural.evidence_trace_lines(ctx, None)
    assert "structural_dynamic_dispatch=cannot_bound_reachable_sinks" in lines
