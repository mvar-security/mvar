"""
Test S1501-05: Fix fail-open/fail-closed contract mismatch in PostToolUse.

Verifies that error messages correctly indicate fail-open audit mode.
"""
import subprocess
import json


def test_posttooluse_error_message_is_fail_open_honest():
    """Verify error path contains 'already executed' and NOT 'blocked for security'."""
    # Read the hook file to verify the error message
    hook_path = "mvar/hooks/governor_hook.py"

    with open(hook_path, 'r') as f:
        content = f.read()

    # Verify the import error handler has correct messaging
    assert "already executed" in content, "Error message should mention 'already executed'"
    assert "PostToolUse audit mode" in content, "Error message should mention 'PostToolUse audit mode'"

    # Verify the OLD incorrect message is NOT present
    assert "Commands blocked for security" not in content, "Should NOT say 'blocked for security' (fail-open mode)"
