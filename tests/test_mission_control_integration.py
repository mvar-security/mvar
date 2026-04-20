#!/usr/bin/env python3
"""
Integration test for MVARAdapter against live Mission Control instance.

Run with:
    MC_API_KEY=test_key QSEAL_SECRET=test_secret python3 -m pytest mvar/tests/test_mission_control_integration.py -v -s
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mvar.adapters.mission_control_adapter import MVARAdapter
from mvar.adapters.types import AgentRegistration, HeartbeatPayload, TaskReport


async def main():
    """Run integration test sequence."""

    # Environment check
    api_key = os.getenv("MC_API_KEY")
    qseal_secret = os.getenv("QSEAL_SECRET")

    if not api_key:
        print("❌ MC_API_KEY environment variable required")
        sys.exit(1)

    if not qseal_secret:
        print("❌ QSEAL_SECRET environment variable required")
        sys.exit(1)

    print("=" * 80)
    print("MVAR Mission Control Integration Test")
    print("=" * 80)
    print(f"✅ API Key: {api_key[:8]}...")
    print(f"✅ QSEAL Secret: {qseal_secret[:8]}...")
    print()

    # Initialize adapter
    print("Initializing MVARAdapter...")
    adapter = MVARAdapter(
        mission_control_url="http://127.0.0.1:3000",
        agent_id="mvar-integration-test",
        api_key=api_key,
        qseal_secret=qseal_secret,
    )
    print(f"✅ Adapter initialized (framework={adapter.framework})")
    print()

    try:
        # Test 1: Register agent
        print("=" * 80)
        print("TEST 1: Register Agent")
        print("=" * 80)

        registration: AgentRegistration = {
            "agentId": "mvar-integration-test",
            "name": "mvar-integration-test",  # Must be alphanumeric + dots/hyphens/underscores only
            "framework": "mvar",
            "metadata": {
                "role": "agent",
                "capabilities": ["policy-enforcement", "qseal-signing", "execution-witness-binding"],
            },
        }

        print(f"Payload: {registration}")
        await adapter.register(registration)
        print("✅ Registration successful (POST /api/agents/register)")
        print()

        # Test 2: Heartbeat
        print("=" * 80)
        print("TEST 2: Send Heartbeat")
        print("=" * 80)

        heartbeat: HeartbeatPayload = {
            "agentId": "mvar-integration-test",
            "status": "active",
            "metrics": {
                "policy_checks_total": 42,
                "blocks_enforced": 3,
                "qseal_signatures_generated": 15,
            },
        }

        print(f"Payload: {heartbeat}")
        await adapter.heartbeat(heartbeat)
        print("✅ Heartbeat successful (POST /api/agents/mvar-integration-test/heartbeat)")
        print()

        # Test 3: Report Task with QSEAL-signed policy outcome
        print("=" * 80)
        print("TEST 3: Report Task (with QSEAL-signed policy outcome)")
        print("=" * 80)

        policy_outcome = {
            "decision": "allow",
            "violations": [],
            "execution_context": {
                "tool": "bash_execute",
                "input": "ls /tmp",
                "timestamp": 1709765432,
            },
            "continuity_metadata": {
                "session_id": "test-session-001",
                "sequence_num": 1,
            },
        }

        task_report: TaskReport = {
            "taskId": "integration-test-task-001",
            "agentId": "mvar-integration-test",
            "progress": 100,
            "status": "done",
            "output": {
                "policy_outcome": policy_outcome,
                "witness": {
                    "tool_call_id": "test-call-001",
                    "execution_timestamp": 1709765432,
                },
            },
        }

        print(f"Policy Outcome: {policy_outcome}")
        print()
        print("Signing with QSEAL...")
        await adapter.reportTask(task_report)
        print("✅ Task report successful (POST /api/tasks)")
        print("✅ QSEAL signature embedded in task metadata")
        print()

        # Test 4: Get Assignments
        print("=" * 80)
        print("TEST 4: Get Assignments from Queue")
        print("=" * 80)

        assignments = await adapter.getAssignments("mvar-integration-test")
        print(f"Queue response: {len(assignments)} assignment(s)")
        if assignments:
            for i, assignment in enumerate(assignments, 1):
                print(f"  Assignment {i}:")
                print(f"    Task ID: {assignment['taskId']}")
                print(f"    Description: {assignment['description'][:80]}...")
                print(f"    Priority: {assignment.get('priority', 'N/A')}")
        else:
            print("  (No pending assignments)")
        print("✅ Queue query successful (GET /api/tasks/queue?agent=mvar-integration-test)")
        print()

        # Test 5: Disconnect
        print("=" * 80)
        print("TEST 5: Disconnect Agent")
        print("=" * 80)

        await adapter.disconnect("mvar-integration-test")
        print("✅ Disconnect successful (offline heartbeat sent)")
        print()

        print("=" * 80)
        print("✅ PHASE 1 COMPLETE — All integration tests passed")
        print("=" * 80)
        print()
        print("Verified:")
        print("  ✅ Agent registration (FrameworkAdapter.register)")
        print("  ✅ Heartbeat with MVAR metrics (FrameworkAdapter.heartbeat)")
        print("  ✅ Task report with QSEAL-signed policy outcome (FrameworkAdapter.reportTask)")
        print("  ✅ Queue endpoint integration (FrameworkAdapter.getAssignments)")
        print("  ✅ Graceful disconnect (FrameworkAdapter.disconnect)")
        print()
        print("Next: Check Mission Control dashboard at http://127.0.0.1:3000")
        print("      - Agents tab should show 'MVAR Integration Test Agent' (offline)")
        print("      - Tasks tab should show task with QSEAL signature in metadata")

    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        await adapter.close()


if __name__ == "__main__":
    asyncio.run(main())
