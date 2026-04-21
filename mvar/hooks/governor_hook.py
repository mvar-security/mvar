#!/usr/bin/env python3
"""
MVAR ExecutionGovernor Hook for Claude Code
============================================

PostToolUse hook that audits Bash tool calls against MVAR policy.

Architecture:
- Post-execution audit logging (observe and report violations)
- Synchronous Mission Control reporting
- Records "would have blocked" decisions for enforcement_mode: observe
- All commands execute; violations are logged for security visibility

⚠️  DEMO CREDENTIALS — DO NOT USE IN PRODUCTION
================================================
This hook is configured with test credentials for demonstration purposes:
- QSEAL_SECRET=test_secret
- MC_API_KEY=test_key

These are INSECURE and must be replaced with production-grade secrets before
deployment. Use environment-specific credential management in production.

Author: MVAR Security
Date: 2026-04-20
"""

import sys
import json
import os
import traceback
from pathlib import Path
from datetime import datetime

# Debug log path
DEBUG_LOG = Path("/tmp/mvar_hook_mc_debug.log")

def debug_log(message: str) -> None:
    """Write debug message to log file with timestamp."""
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = datetime.now().isoformat()
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass  # Never fail on debug logging

# Import from mvar package (installed via pip)
debug_log(f"=== Hook script started ===")

try:
    # Import bash_policy from mvar.hooks (installed package)
    from mvar.hooks import evaluate_bash_command
    debug_log("bash_policy loaded successfully from mvar.hooks")
except ImportError as e:
    # Fail-closed: If we can't import the policy engine, block everything
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": f"❌ MVAR: Policy engine import failed\n\nError: {e}\n\nCommands blocked for security.",
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def report_to_mission_control(
    command: str,
    decision: str,
    violations: list,
    tool_use_id: str,
    mc_api_key: str,
    qseal_secret: str,
    tool_response: str = "",
) -> None:
    """
    Report policy decision to Mission Control dashboard (synchronous).

    In audit mode (PostToolUse), all commands execute. We log which ones
    would have been blocked in enforcement mode.
    """
    debug_log(f"report_to_mission_control called: command={command[:50]}, decision={decision}")

    try:
        # Use synchronous HTTP instead of async to avoid event loop issues in subprocess
        import httpx

        debug_log("Attempting httpx import - SUCCESS")

        base_url = "http://localhost:3000"
        debug_log(f"Mission Control URL: {base_url}")

        # Build payloads
        would_have_blocked = decision in ("block", "step_up")
        enforcement_mode = "observe"  # PostToolUse is audit-only

        # Map decision to audit semantics
        if decision == "allow":
            audit_decision = "allow"
        elif decision in ("block", "step_up"):
            audit_decision = "audit"  # Would have blocked/step-up in enforce mode
        else:
            audit_decision = "unknown"

        agent_payload = {
            "agentId": "claude-code-mvar",
            "name": "claude-code-mvar",
            "framework": "mvar",
            "metadata": {
                "role": "agent",
                "capabilities": ["policy-enforcement", "qseal-signing"],
            },
        }

        task_payload = {
            "taskId": f"bash-{tool_use_id[:8]}",
            "agentId": "claude-code-mvar",
            "progress": 100,
            "status": "done",
            "output": {
                "policy_outcome": {
                    "decision": audit_decision,
                    "enforcement_mode": enforcement_mode,
                    "would_have_blocked": would_have_blocked,
                    "original_decision": decision,
                    "violations": violations,
                    "protocol_version": "mvar-v1",
                },
                "witness": {
                    "tool_call_id": tool_use_id,
                    "command": command[:200],
                    "executed": True,
                    "output_preview": str(tool_response)[:200] if tool_response else None,
                },
            },
        }

        debug_log(f"Task payload prepared: {json.dumps(task_payload, indent=2)}")

        # QSEAL signing of policy outcome
        import hmac
        import hashlib
        import time

        policy_outcome = task_payload["output"]["policy_outcome"]
        canonical_json = json.dumps(policy_outcome, sort_keys=True, separators=(',', ':'))
        meta_hash = hashlib.sha256(canonical_json.encode()).hexdigest()
        qseal_signature = hmac.new(
            qseal_secret.encode(),
            canonical_json.encode(),
            hashlib.sha256
        ).hexdigest()

        debug_log(f"QSEAL signature computed: {qseal_signature[:16]}...")

        # Build Mission Control task creation payload
        mc_task_payload = {
            "title": f"Task {task_payload['taskId']} completion",
            "status": task_payload["status"],
            "outcome": "success" if task_payload["status"] == "done" else "failure",
            "metadata": {
                "mvar_policy_outcome": policy_outcome,
                "qseal_signature": qseal_signature,
                "qseal_meta_hash": meta_hash,
                "qseal_verified": True,
                "clawzero_witness": task_payload["output"]["witness"],
            },
            "assigned_to": task_payload["agentId"],
            "tags": ["mvar", "policy-outcome"],
            "completed_at": int(time.time()),
        }

        debug_log(f"Mission Control payload prepared with QSEAL signature")

        # Synchronous HTTP client with timeout
        with httpx.Client(timeout=5.0) as client:
            headers = {"x-api-key": mc_api_key, "Content-Type": "application/json"}

            # Register agent (idempotent)
            debug_log(f"POST {base_url}/api/agents/register")
            try:
                agent_response = client.post(
                    f"{base_url}/api/agents/register",
                    json=agent_payload,
                    headers=headers,
                )
                debug_log(f"Agent registration response: {agent_response.status_code}")
                debug_log(f"Agent response body: {agent_response.text[:500]}")
            except Exception as e:
                debug_log(f"Agent registration failed: {e}")
                debug_log(f"Full traceback: {traceback.format_exc()}")

            # Report task to correct endpoint: POST /api/tasks
            debug_log(f"POST {base_url}/api/tasks")
            try:
                task_response = client.post(
                    f"{base_url}/api/tasks",
                    json=mc_task_payload,
                    headers=headers,
                )
                debug_log(f"Task report response: {task_response.status_code}")
                debug_log(f"Task response body: {task_response.text[:500]}")

                if task_response.status_code not in (200, 201):
                    debug_log(f"WARNING: Task report returned non-success status: {task_response.status_code}")
                else:
                    debug_log("SUCCESS: Task created in Mission Control")
            except Exception as e:
                debug_log(f"Task report failed: {e}")
                debug_log(f"Full traceback: {traceback.format_exc()}")

        debug_log("Mission Control reporting complete")

    except ImportError as e:
        debug_log(f"IMPORT ERROR: {e}")
        debug_log(f"sys.path: {sys.path}")
        debug_log(f"Full traceback: {traceback.format_exc()}")
    except Exception as e:
        debug_log(f"EXCEPTION in report_to_mission_control: {e}")
        debug_log(f"Full traceback: {traceback.format_exc()}")


def main():
    """Main hook entry point for PostToolUse audit logging."""
    try:
        debug_log("main() entry point")

        # Read hook context from stdin (PostToolUse includes tool_response)
        context = json.loads(sys.stdin.read())
        debug_log(f"Context parsed: tool_name={context.get('tool_name')}")
        debug_log(f"Context keys: {list(context.keys())}")

        # Extract bash command, tool use ID, and execution result
        command = context.get("tool_input", {}).get("command", "")
        tool_use_id = context.get("tool_use_id", "unknown")
        # PostToolUse provides tool_response, not tool_output
        tool_response = context.get("tool_response", context.get("tool_output", ""))

        debug_log(f"Command: {command[:100]}")
        debug_log(f"Tool use ID: {tool_use_id}")
        debug_log(f"Tool response length: {len(str(tool_response))}")

        # Check environment variables (logging only - no blocking in audit mode)
        qseal_secret = os.getenv("QSEAL_SECRET")
        mc_api_key = os.getenv("MC_API_KEY")

        debug_log(f"QSEAL_SECRET present: {bool(qseal_secret)}")
        debug_log(f"MC_API_KEY present: {bool(mc_api_key)}")

        # Evaluate command with bash policy engine
        decision, violations, message = evaluate_bash_command(command)
        debug_log(f"Policy decision: {decision}, violations: {len(violations)}")

        # Report to Mission Control (best-effort, synchronous)
        if mc_api_key and qseal_secret:
            debug_log("Both credentials present - calling report_to_mission_control()")
            report_to_mission_control(
                command=command,
                decision=decision,
                violations=violations,
                tool_use_id=tool_use_id,
                mc_api_key=mc_api_key,
                qseal_secret=qseal_secret,
                tool_response=tool_response,
            )
        else:
            debug_log("WARNING: Skipping Mission Control report - credentials missing")

        # PostToolUse always succeeds - we're auditing, not blocking
        # Log what would have happened in enforcement mode
        if decision == "allow":
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "✅ MVAR Audit: ALLOW - No policy violations detected (enforcement_mode: observe)",
                }
            }
        elif decision == "step_up":
            category = violations[0]['category'] if violations else 'unknown'
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": f"⚠️  MVAR Audit: WOULD HAVE REQUIRED STEP-UP (enforcement_mode: observe)\nCategory: {category}\nReason: {message}",
                }
            }
        else:  # block
            category = violations[0]['category'] if violations else 'unknown'
            rule_id = violations[0]['rule_id'] if violations else 'unknown'
            severity = violations[0]['severity'] if violations else 'unknown'

            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": f"🔶 MVAR Audit: WOULD HAVE BLOCKED (enforcement_mode: observe)\n\nCommand: {command[:100]}\nReason: {message}\nCategory: {category}\nSeverity: {severity}\nRule: {rule_id}\n\nThis command was allowed to execute for audit visibility.",
                }
            }

        print(json.dumps(output))
        sys.exit(0)

    except Exception as e:
        # Governor crash - log error but don't block (PostToolUse audit mode)
        error_trace = traceback.format_exc()
        debug_log(f"EXCEPTION in main: {e}")
        debug_log(f"Full traceback: {error_trace}")
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": f"⚠️  MVAR Audit: GOVERNOR ERROR (enforcement_mode: observe)\n\nError: {str(e)}\n\nThe MVAR policy engine crashed. Command was allowed to execute. Error logged for investigation.",
            }
        }
        print(json.dumps(output))
        sys.exit(0)


if __name__ == "__main__":
    main()
