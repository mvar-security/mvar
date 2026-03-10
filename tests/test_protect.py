from __future__ import annotations

import inspect
from typing import Any, Dict

import pytest

import mvar
from mvar import ExecutionBlocked, StepUpRequired, protect
from mvar_core.profiles import SecurityProfile


class _FakeDecision:
    def __init__(
        self,
        *,
        outcome: str = "allow",
        reason: str = "allowed",
        integrity: str = "trusted",
        risk: str = "low",
    ) -> None:
        self.decision_id = "decision-test"
        self._outcome = outcome
        self._reason = reason
        self._integrity = integrity
        self._risk = risk
        self.execution_token = {"token": "unit-test-token"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self._outcome,
            "reason": self._reason,
            "sink": {
                "tool": "test_tool",
                "action": "execute",
                "risk": self._risk,
                "rationale": "unit-test",
            },
            "provenance": {
                "node_id": "prov-1",
                "source": "unit-test",
                "integrity": self._integrity,
                "confidentiality": "public",
                "taint_tags": [],
            },
            "evaluation_trace": ["unit-test-trace"],
            "timestamp": "2026-03-07T00:00:00Z",
            "qseal_signature": {"algo": "ed25519", "sig": "unit-test"},
        }


def _install_fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    outcome: str = "allow",
    reason: str = "allowed",
    integrity: str = "trusted",
    risk: str = "low",
) -> Dict[str, Any]:
    captured: Dict[str, Any] = {"calls": []}

    class _FakeAdapter:
        def __init__(self, policy: object, graph: object) -> None:
            self.policy = policy
            self.graph = graph

        def create_user_provenance(self, text: str) -> str:
            captured["user_provenance_text"] = text
            return "trusted-node"

        def create_untrusted_provenance(self, text: str, source: str = "external_doc") -> str:
            captured["untrusted_provenance_text"] = text
            captured["untrusted_provenance_source"] = source
            return "untrusted-node"

        def evaluate(
            self,
            tool: str,
            action: str,
            target: str,
            provenance_node_id: str,
            parameters: Dict[str, Any] | None = None,
        ) -> _FakeDecision:
            captured.setdefault("evaluate_calls", []).append(
                {
                    "tool": tool,
                    "action": action,
                    "target": target,
                    "provenance_node_id": provenance_node_id,
                    "parameters": parameters,
                }
            )
            return _FakeDecision(
                outcome=outcome,
                reason=reason,
                integrity=integrity,
                risk=risk,
            )

        def authorize_execution(
            self,
            tool: str,
            action: str,
            target: str,
            provenance_node_id: str,
            parameters: Dict[str, Any] | None = None,
            execution_token: Dict[str, Any] | None = None,
            pre_evaluated_decision: Any | None = None,
        ) -> _FakeDecision:
            captured["calls"].append(
                {
                    "tool": tool,
                    "action": action,
                    "target": target,
                    "provenance_node_id": provenance_node_id,
                    "parameters": parameters,
                    "execution_token": execution_token,
                    "pre_evaluated_decision": pre_evaluated_decision,
                }
            )
            return _FakeDecision(
                outcome=outcome,
                reason=reason,
                integrity=integrity,
                risk=risk,
            )

    def _fake_create_default_runtime(profile: SecurityProfile, **kwargs: Any) -> tuple[object, object, object]:
        captured["profile"] = profile
        return object(), object(), object()

    monkeypatch.setattr(mvar, "MVARExecutionAdapter", _FakeAdapter)
    monkeypatch.setattr(mvar, "create_default_runtime", _fake_create_default_runtime)
    return captured


def test_protect_returns_callable(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch)

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool)
    assert callable(wrapped)


def test_protect_preserves_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch)

    def tool(a: str, b: int = 1, *, c: bool = False) -> str:
        """tool docs"""
        return f"{a}:{b}:{c}"

    wrapped = protect(tool)
    assert wrapped.__name__ == tool.__name__
    assert wrapped.__doc__ == tool.__doc__
    assert inspect.signature(wrapped) == inspect.signature(tool)
    assert wrapped("x", 2, c=True) == "x:2:True"


def test_protect_allow_invokes_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch, outcome="allow", integrity="trusted", risk="low")
    calls = {"count": 0}

    def tool(command: str) -> str:
        calls["count"] += 1
        return f"ok:{command}"

    wrapped = protect(tool)
    result = wrapped("ls -la")
    assert result == "ok:ls -la"
    assert calls["count"] == 1


def test_protect_block_raises_execution_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(
        monkeypatch,
        outcome="block",
        reason="blocked-by-policy",
        integrity="untrusted",
        risk="critical",
    )

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool)
    with pytest.raises(ExecutionBlocked) as exc:
        wrapped("cat /etc/shadow")

    assert exc.value.decision["outcome"] == "BLOCK"
    assert exc.value.decision["reason"] == "blocked-by-policy"


def test_protect_step_up_raises_step_up_required(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(
        monkeypatch,
        outcome="step_up",
        reason="approval-required",
        integrity="untrusted",
        risk="high",
    )

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool)
    with pytest.raises(StepUpRequired) as exc:
        wrapped("write sensitive data")

    assert exc.value.decision["outcome"] == "STEP_UP"
    assert exc.value.decision["reason"] == "approval-required"


def test_protect_default_profile_is_balanced(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool)
    assert wrapped("echo hello") == "echo hello"
    assert captured["profile"] == SecurityProfile.BALANCED


def test_protect_no_signal_preserves_default_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, signal=None)
    assert wrapped("echo hello") == "echo hello"
    assert captured["profile"] == SecurityProfile.BALANCED


def test_protect_high_uncertainty_signal_tightens_to_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, signal={"uncertainty_score": 0.91}, profile="permissive")
    assert wrapped("whoami") == "whoami"
    assert captured["profile"] == SecurityProfile.STRICT


def test_protect_low_uncertainty_signal_does_not_change_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, signal={"uncertainty_score": 0.8}, profile="permissive")
    assert wrapped("whoami") == "whoami"
    assert captured["profile"] == SecurityProfile.MONITOR


def test_protect_malformed_signal_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, signal={"uncertainty_score": "not-a-number"}, profile="balanced")
    assert wrapped("id") == "id"
    assert captured["profile"] == SecurityProfile.BALANCED


def test_protect_strict_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, profile="strict")
    assert wrapped("id") == "id"
    assert captured["profile"] == SecurityProfile.STRICT


def test_protect_permissive_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, profile="permissive")
    assert wrapped("whoami") == "whoami"
    assert captured["profile"] == SecurityProfile.MONITOR


def test_protect_invalid_profile_raises_value_error() -> None:
    def tool(command: str) -> str:
        return command

    with pytest.raises(ValueError):
        protect(tool, profile="unknown")


def test_protect_non_callable_raises_type_error() -> None:
    with pytest.raises(TypeError):
        protect("not_a_function")  # type: ignore[arg-type]


def test_protect_decision_record_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch, outcome="block", integrity="untrusted", risk="critical")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool)
    with pytest.raises(ExecutionBlocked) as exc:
        wrapped("cat /etc/shadow")

    decision = exc.value.decision
    required_keys = {"apiVersion", "kind", "outcome", "reason", "integrity", "audit"}
    assert required_keys.issubset(decision.keys())
    assert decision["kind"] == "DecisionRecord"
    assert isinstance(decision["audit"], dict)


def test_protect_called_twice_same_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")
    calls = {"count": 0}

    def tool(command: str) -> str:
        calls["count"] += 1
        return f"ran:{command}"

    wrapped = protect(tool)
    first = wrapped("echo one")
    second = wrapped("echo two")

    assert first == "ran:echo one"
    assert second == "ran:echo two"
    assert calls["count"] == 2
    assert len(captured["calls"]) == 2
    assert captured["calls"][0]["provenance_node_id"] == captured["calls"][1]["provenance_node_id"]


def test_protect_infers_bash_exec_action(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str) -> str:
        return command

    wrapped = protect(tool, tool_name="bash")
    assert wrapped("ls /tmp") == "ls /tmp"
    assert captured["calls"][-1]["action"] == "exec"


def test_protect_infers_http_post_action(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(target: str, **kwargs: Any) -> str:
        return target

    wrapped = protect(tool, tool_name="http")
    assert wrapped("https://api.example.com/upload", method="POST") == "https://api.example.com/upload"
    assert captured["calls"][-1]["action"] == "post"


def test_protect_passes_pre_evaluated_decision_and_token(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_runtime(monkeypatch, outcome="allow")

    def tool(command: str, *, dry_run: bool = False) -> str:
        assert dry_run is True
        return command

    wrapped = protect(tool, tool_name="bash")
    assert wrapped("echo hello", dry_run=True) == "echo hello"
    assert captured["calls"][-1]["pre_evaluated_decision"] is not None
    assert captured["calls"][-1]["execution_token"] == {"token": "unit-test-token"}
