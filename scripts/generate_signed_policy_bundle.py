#!/usr/bin/env python3
"""Generate signed policy bundle for startup verification gate."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MVAR_CORE = REPO_ROOT / "mvar-core"
for candidate in (str(REPO_ROOT), str(MVAR_CORE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from capability import CapabilityRuntime  # noqa: E402
from provenance import ProvenanceGraph  # noqa: E402
from sink_policy import SinkPolicy, register_common_sinks  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path to write signed policy bundle JSON")
    parser.add_argument("--issuer", default="mvar_launch_gate", help="Bundle issuer name")
    parser.add_argument("--secret", default="", help="Policy bundle signing secret (or env fallback)")
    args = parser.parse_args()

    secret = args.secret or os.getenv("MVAR_POLICY_BUNDLE_SECRET") or os.getenv("MVAR_EXEC_TOKEN_SECRET") or os.getenv("QSEAL_SECRET")
    if not secret:
        print("ERROR: missing policy bundle secret", file=sys.stderr)
        return 1

    os.environ["MVAR_POLICY_BUNDLE_SECRET"] = secret
    os.environ["MVAR_POLICY_BUNDLE_PATH"] = args.out
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"

    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)

    bundle = policy.write_signed_policy_bundle(bundle_path=args.out, issuer=args.issuer)
    print(json.dumps({"policy_hash": bundle["policy_hash"], "bundle_path": args.out}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
