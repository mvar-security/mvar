"""Structural-dependency-aware enforcement: derived-capability inputs for MVAR.

Derives, at the one-time ``protect()`` wrap moment, the set of sensitive sinks
*actually reachable* from a tool's implementation (multi-hop:
``tool -> helper -> requests.post``) and exposes it as a fourth policy axis —
enforcement on what the executing code is structurally wired to reach, not on
the tool's self-description. Semantic capability drift (the reachable-sink set
*widening* across re-wraps of the same tool) is detected and re-gated.

Honest scope claim: structural-dependency-aware enforcement, not present in
the shipped enforcement field we surveyed (July 2026) — a first-to-ship
integration claim, not "nobody does this".

Decoupling invariants (spec §2.2 — these are features):
- Pure derivation: this package never imports the governor; the governor never
  imports this package. Consumers receive a plain serializable dict.
- Escalate-only: a structural finding can never override or downgrade a block.
- Fail-closed to flat: if derivation is unavailable or fails, enforcement
  falls back to the existing flat behavior — never fails open on a positive
  finding, never crashes the wrap.
"""

from __future__ import annotations

from typing import Any, Optional

from mvar.structural.sinks import (  # noqa: F401 (re-exported)
    CRITICAL_CLASSES,
    INFORMATIONAL_CLASSES,
    STEP_UP_CLASSES,
)

REASON_SINK_REACHABLE = "STRUCTURAL_SINK_REACHABLE"
REASON_CAPABILITY_DRIFT = "STRUCTURAL_CAPABILITY_DRIFT"

# In-process drift baselines: first derived class-set per tool identity.
# v0.1 scope, stated plainly: drift is detected within a process lifetime
# (re-wrap after a tool update / hot reload); cross-process persistence is a
# later version's contract decision.
_baseline_registry: dict[str, frozenset[str]] = {}


def reset_baselines() -> None:
    """Clear drift baselines (test support / explicit re-approval)."""
    _baseline_registry.clear()


def derive_structural_context(tool_fn: Any, *, hop_limit: int = 6) -> Optional[dict[str, Any]]:
    """Analyze ``tool_fn`` and return the structural context dict, or None.

    Never raises: any analysis failure returns None, which callers treat as
    "derivation absent" -> the existing flat axes govern unchanged.
    """
    try:
        from mvar.structural.analyzer import analyze_callable

        context = analyze_callable(tool_fn, hop_limit=hop_limit)
    except Exception:
        return None
    if context is None:
        return None
    key = str(context.get("tool"))
    classes = frozenset(context.get("reachable_sinks") or {})
    baseline = _baseline_registry.get(key)
    if baseline is None:
        _baseline_registry[key] = classes
        context["capability_drift"] = False
        context["new_sinks"] = []
    else:
        new = sorted(classes - baseline)
        context["capability_drift"] = bool(new)
        context["new_sinks"] = new
    return context


def evaluate_structural(
    context: dict[str, Any],
    authorized_classes: frozenset[str] | set[str],
) -> Optional[dict[str, Any]]:
    """Pure decision helper: compare reachable sinks against what the declared
    action authorizes. Returns a finding dict or None. Escalate-only by
    construction — the return value only ever *adds* a reason to block or
    step up, never a reason to allow."""
    if not isinstance(context, dict):
        return None
    reachable = context.get("reachable_sinks")
    if not isinstance(reachable, dict):
        reachable = {}
    unauthorized = {c: v for c, v in reachable.items() if c not in authorized_classes}

    critical = sorted(set(unauthorized) & CRITICAL_CLASSES)
    if critical:
        return {
            "code": REASON_SINK_REACHABLE,
            "severity": "block",
            "classes": critical,
            "evidence": {c: unauthorized[c] for c in critical},
        }
    step_up = sorted(set(unauthorized) & STEP_UP_CLASSES)
    if step_up:
        return {
            "code": REASON_SINK_REACHABLE,
            "severity": "step_up",
            "classes": step_up,
            "evidence": {c: unauthorized[c] for c in step_up},
        }
    if context.get("capability_drift"):
        return {
            "code": REASON_CAPABILITY_DRIFT,
            "severity": "step_up",
            "classes": sorted(context.get("new_sinks") or []),
            "evidence": {},
        }
    return None


def evidence_trace_lines(context: dict[str, Any], finding: Optional[dict[str, Any]]) -> list[str]:
    """Trace lines shared by both consuming surfaces (wrapper + governor)."""
    reachable = context.get("reachable_sinks") if isinstance(context, dict) else {}
    lines = [
        "structural_reachable=" + (",".join(sorted(reachable)) if reachable else "none")
    ]
    if isinstance(context, dict) and context.get("dynamic_dispatch"):
        lines.append("structural_dynamic_dispatch=cannot_bound_reachable_sinks")
    if finding:
        for cls in finding["classes"]:
            info = finding["evidence"].get(cls)
            if isinstance(info, dict) and info.get("path"):
                lines.append(f"structural_evidence={cls}:" + "→".join(str(p) for p in info["path"]))
        lines.append(f"structural_elevation={finding['code']}")
    return lines


__all__ = [
    "REASON_SINK_REACHABLE",
    "REASON_CAPABILITY_DRIFT",
    "CRITICAL_CLASSES",
    "STEP_UP_CLASSES",
    "INFORMATIONAL_CLASSES",
    "derive_structural_context",
    "evaluate_structural",
    "evidence_trace_lines",
    "reset_baselines",
]
