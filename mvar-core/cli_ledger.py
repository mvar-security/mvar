"""
MVAR Decision Ledger CLI

Command-line tools for inspecting and managing MVAR decision ledger.

Commands:
- mvar-report: List recent decisions
- mvar-explain <decision_id>: Show full details of a decision
- mvar-allow add <decision_id>: Create override for a blocked decision
- mvar-allow list: List active overrides
- mvar-allow expire <override_id>: Revoke an override

Usage:
    export MVAR_ENABLE_LEDGER=1
    export QSEAL_SECRET=$(openssl rand -hex 32)

    # Run agent, generate some BLOCK decisions
    # ...

    # Inspect decisions
    mvar-report

    # Explain a specific decision
    mvar-explain MVAR_DEC_20260224T120000Z_a1b2c3d4

    # Create 24h override
    mvar-allow add MVAR_DEC_20260224T120000Z_a1b2c3d4

    # List active overrides
    mvar-allow list

    # Revoke override
    mvar-allow expire MVAR_OVR_20260224T120500Z_e5f6g7h8
"""

import sys
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .decision_ledger import MVARDecisionLedger


def _principal_id() -> str:
    return os.getenv(
        "MVAR_PRINCIPAL_ID",
        f"local_install:{hashlib.sha256(str(Path.cwd()).encode('utf-8')).hexdigest()[:12]}",
    )


def _init_ledger_or_exit() -> MVARDecisionLedger:
    try:
        return MVARDecisionLedger()
    except Exception as exc:
        print(f"❌ Unable to initialize decision ledger: {exc}")
        print("Tip: set QSEAL_SECRET when MVAR_ENABLE_LEDGER=1")
        raise SystemExit(1)


def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp for display"""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso_timestamp


def mvar_report():
    """List recent MVAR decisions"""
    if os.getenv("MVAR_ENABLE_LEDGER") != "1":
        print("⚠️  MVAR_ENABLE_LEDGER not set to 1")
        print("Export MVAR_ENABLE_LEDGER=1 to enable decision ledger")
        sys.exit(1)

    ledger = _init_ledger_or_exit()
    decisions = ledger.load_decisions(limit=20)

    if not decisions:
        raw_scrolls = ledger._load_scrolls_raw()
        if raw_scrolls:
            print("No verified decisions available.")
            print()
            print("Possible cause: signature verification mismatch.")
            print("If running HMAC fallback mode, ensure QSEAL_SECRET matches the value")
            print("used when decisions were recorded.")
        else:
            print("No decisions recorded yet.")
        sys.exit(0)

    print(f"\n{'='*80}")
    print(f"MVAR Decision Ledger Report (most recent {len(decisions)} decisions)")
    print(f"{'='*80}\n")

    for i, decision in enumerate(decisions, 1):
        outcome = decision["decision_outcome"]
        outcome_upper = str(outcome).upper()
        timestamp = format_timestamp(decision["timestamp"])
        sink = decision["sink_target"]
        tool_action = f"{sink['tool']}.{sink['action']}"
        target_hash = sink["target_hash"][:8] + "..."
        reason = decision["reason"][:60] + "..." if len(decision["reason"]) > 60 else decision["reason"]

        # Color-code outcomes
        if outcome_upper == "BLOCK":
            outcome_display = f"🛑 {outcome_upper}"
        elif outcome_upper == "STEP_UP":
            outcome_display = f"⚠️  {outcome_upper}"
        else:
            outcome_display = f"✅ {outcome_upper}"

        print(f"{i}. {timestamp}")
        print(f"   {outcome_display} :: {tool_action} (target: {target_hash})")
        print(f"   Reason: {reason}")
        print(f"   ID: {decision['scroll_id']}")
        print()

    print(f"{'='*80}\n")
    print(f"Use 'mvar-explain <decision_id>' for full details")
    print(f"Use 'mvar-allow add <decision_id>' to create override\n")


def mvar_explain(decision_id: str):
    """Explain a specific decision"""
    if os.getenv("MVAR_ENABLE_LEDGER") != "1":
        print("⚠️  MVAR_ENABLE_LEDGER not set to 1")
        sys.exit(1)

    ledger = _init_ledger_or_exit()
    decision = ledger.get_decision(decision_id)

    if not decision:
        print(f"❌ Decision {decision_id} not found")
        sys.exit(1)

    print(f"\n{'='*80}")
    print(f"MVAR Decision Details")
    print(f"{'='*80}\n")

    print(f"Decision ID:  {decision['scroll_id']}")
    print(f"Timestamp:    {format_timestamp(decision['timestamp'])}")
    print(f"Outcome:      {decision['decision_outcome']}")
    print()

    print(f"Sink Target:")
    sink = decision["sink_target"]
    print(f"  Tool:        {sink['tool']}")
    print(f"  Action:      {sink['action']}")
    print(f"  Target Hash: {sink['target_hash']}")
    print()

    print(f"Provenance:   {decision['provenance_node_id']}")
    print(f"Principal:    {decision.get('principal_id', 'local_install')}")
    print(f"Reason:       {decision['reason']}")
    print()

    print(f"Evaluation Trace:")
    for step in decision.get("evaluation_trace", []):
        print(f"  - {step}")
    print()

    # Verify QSEAL signature
    print(f"QSEAL Signature:")
    print(f"  Algorithm:   {decision.get('qseal_algorithm', 'unknown')}")
    print(f"  Meta Hash:   {decision.get('meta_hash', 'none')[:16]}...")
    verified = ledger._verify_scroll(decision)
    print(f"  Verified:    {'✅ VALID' if verified else '❌ INVALID'}")
    print()

    if decision["decision_outcome"] in ("BLOCK", "STEP_UP"):
        print(f"To create 24h override: mvar-allow add {decision['scroll_id']}\n")


def mvar_allow_add():
    """Create override for a blocked decision"""
    if os.getenv("MVAR_ENABLE_LEDGER") != "1":
        print("⚠️  MVAR_ENABLE_LEDGER not set to 1")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Usage: mvar-allow add <decision_id> [ttl_hours]")
        print("Example: mvar-allow add MVAR_DEC_20260224T120000Z_a1b2c3d4 24")
        sys.exit(1)

    decision_id = sys.argv[2]
    ttl_hours = int(sys.argv[3]) if len(sys.argv) > 3 else 24

    ledger = _init_ledger_or_exit()

    # Validate decision exists
    decision = ledger.get_decision(decision_id)
    if not decision:
        print(f"❌ Decision {decision_id} not found")
        sys.exit(1)

    if decision["decision_outcome"] not in ("BLOCK", "STEP_UP"):
        print(f"❌ Can only override BLOCK/STEP_UP decisions, got {decision['decision_outcome']}")
        sys.exit(1)

    # Show what will be overridden
    print(f"\n{'='*80}")
    print(f"Create Override")
    print(f"{'='*80}\n")
    print(f"Original Decision:")
    print(f"  ID:       {decision['scroll_id']}")
    print(f"  Outcome:  {decision['decision_outcome']}")
    print(f"  Reason:   {decision['reason']}")
    print()

    sink = decision["sink_target"]
    print(f"Override Scope (exact matching):")
    print(f"  Tool:        {sink['tool']}")
    print(f"  Action:      {sink['action']}")
    print(f"  Target Hash: {sink['target_hash']}")
    print(f"  TTL:         {ttl_hours} hours")
    print()

    # Confirm with user
    response = input("Create override? [y/N]: ").strip().lower()
    if response not in ("y", "yes"):
        print("Cancelled.")
        sys.exit(0)

    # Create override
    try:
        override_id = ledger.create_override(
            original_decision_id=decision_id,
            principal_id=_principal_id(),
            ttl_hours=ttl_hours
        )
        print(f"\n✅ Override created: {override_id}")
        print(f"   Expires in {ttl_hours} hours")
        print(f"\n   Use 'mvar-allow expire {override_id}' to revoke early\n")
    except Exception as e:
        print(f"❌ Failed to create override: {e}")
        sys.exit(1)


def mvar_allow_list():
    """List active overrides"""
    if os.getenv("MVAR_ENABLE_LEDGER") != "1":
        print("⚠️  MVAR_ENABLE_LEDGER not set to 1")
        sys.exit(1)

    ledger = _init_ledger_or_exit()
    overrides = ledger.load_overrides()

    # Load expiries (revocations)
    expiries = ledger._load_scrolls(scroll_type="expiry")
    revoked_ids = {e["revoked_override_id"] for e in expiries}

    # Filter active overrides (not expired, not revoked)
    now = datetime.now(timezone.utc)
    active = []
    for override in overrides:
        expiry_time = datetime.fromisoformat(override["ttl_expiry"].replace("Z", "+00:00"))
        if now < expiry_time and override["scroll_id"] not in revoked_ids:
            active.append(override)

    if not active:
        print("No active overrides.")
        sys.exit(0)

    print(f"\n{'='*80}")
    print(f"Active MVAR Overrides ({len(active)})")
    print(f"{'='*80}\n")

    for i, override in enumerate(active, 1):
        expiry = format_timestamp(override["ttl_expiry"])
        criteria = override["match_criteria"]
        tool_action = f"{criteria['tool']}.{criteria['action']}"
        target_hash = criteria["target_hash"][:8] + "..."

        print(f"{i}. Override ID: {override['scroll_id']}")
        print(f"   Created:     {format_timestamp(override['timestamp'])}")
        print(f"   Expires:     {expiry}")
        print(f"   Scope:       {tool_action} (target: {target_hash})")
        print(f"   Original:    {override['parent_decision_id']}")
        print()

    print(f"{'='*80}\n")
    print(f"Use 'mvar-allow expire <override_id>' to revoke\n")


def mvar_allow_expire():
    """Revoke an override"""
    if os.getenv("MVAR_ENABLE_LEDGER") != "1":
        print("⚠️  MVAR_ENABLE_LEDGER not set to 1")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Usage: mvar-allow expire <override_id>")
        print("Example: mvar-allow expire MVAR_OVR_20260224T120500Z_e5f6g7h8")
        sys.exit(1)

    override_id = sys.argv[2]

    ledger = _init_ledger_or_exit()

    # Validate override exists
    overrides = ledger.load_overrides()
    override = None
    for o in overrides:
        if o["scroll_id"] == override_id:
            override = o
            break

    if not override:
        print(f"❌ Override {override_id} not found")
        sys.exit(1)

    # Confirm revocation
    print(f"\n{'='*80}")
    print(f"Revoke Override")
    print(f"{'='*80}\n")
    print(f"Override ID:  {override['scroll_id']}")
    print(f"Created:      {format_timestamp(override['timestamp'])}")
    print(f"Expires:      {format_timestamp(override['ttl_expiry'])}")
    print()

    response = input("Revoke this override? [y/N]: ").strip().lower()
    if response not in ("y", "yes"):
        print("Cancelled.")
        sys.exit(0)

    # Revoke
    try:
        expiry_id = ledger.expire_override(override_id)
        print(f"\n✅ Override {override_id} revoked")
        print(f"   Expiry ID: {expiry_id}\n")
    except Exception as e:
        print(f"❌ Failed to revoke override: {e}")
        sys.exit(1)


# Entry points for setup.py console_scripts
def main_report():
    """Entry point for 'mvar report'"""
    mvar_report()


def main_explain():
    """Entry point for 'mvar-explain' binary"""
    if len(sys.argv) < 2:
        print("Usage: mvar-explain <decision_id>")
        sys.exit(1)
    mvar_explain(sys.argv[1])


def main_allow():
    """Entry point for 'mvar-allow' binary"""
    if len(sys.argv) < 2:
        print("Usage: mvar-allow <add|list|expire> [args...]")
        print()
        print("Subcommands:")
        print("  add <decision_id> [ttl_hours]  - Create override")
        print("  list                           - List active overrides")
        print("  expire <override_id>           - Revoke override")
        sys.exit(1)

    subcommand = sys.argv[1]
    if subcommand == "add":
        mvar_allow_add()
    elif subcommand == "list":
        mvar_allow_list()
    elif subcommand == "expire":
        mvar_allow_expire()
    else:
        print(f"❌ Unknown subcommand: {subcommand}")
        print("Valid subcommands: add, list, expire")
        sys.exit(1)
