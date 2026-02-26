#!/usr/bin/env python3
"""Run community-submitted attack vectors against MVAR sink policy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "mvar-core"))

from provenance import ProvenanceGraph, provenance_external_doc  # noqa: E402
from sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks  # noqa: E402
from capability import CapabilityRuntime  # noqa: E402


def run_vector(policy: SinkPolicy, graph: ProvenanceGraph, vector: dict) -> tuple[str, str, str]:
    node = provenance_external_doc(
        graph,
        content=vector["payload"],
        doc_url=f"community://{vector['id']}"
    )

    sink = vector["sink"]
    decision = policy.evaluate(
        tool=sink["tool"],
        action=sink["action"],
        target=sink.get("target", sink["tool"]),
        provenance_node_id=node.node_id,
    )
    return vector["id"], decision.outcome.value.upper(), vector["expected_outcome"].upper()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: community_attack_harness.py <submission.json>", file=sys.stderr)
        return 2

    submission_path = Path(sys.argv[1])
    submission = json.loads(submission_path.read_text(encoding="utf-8"))

    graph = ProvenanceGraph(enable_qseal=False)
    policy = SinkPolicy(CapabilityRuntime(), graph, enable_qseal=False)
    register_common_sinks(policy)

    failures = []
    for vector in submission["vectors"]:
        vec_id, actual, expected = run_vector(policy, graph, vector)
        status = "PASS" if actual == expected else "FAIL"
        print(f"[{status}] {vec_id}: expected={expected} actual={actual}")
        if status == "FAIL":
            failures.append(vec_id)

    if failures:
        print(f"\ncommunity harness failed ({len(failures)} vectors): {', '.join(failures)}")
        return 1

    print(f"\ncommunity harness passed ({len(submission['vectors'])} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
