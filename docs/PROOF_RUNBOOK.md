# 10-Minute Proof Runbook

**Goal:** Prove MVAR audits policy decisions and produces cryptographically signed evidence.

**Time:** 10 minutes from zero to signed artifact

**Prerequisites:**
- macOS or Linux (Windows WSL2 works)
- Python 3.10+
- Claude Code installed

---

## Step 1: Install MVAR (2 minutes)

```bash
# Install package
pip install mvar-security

# Verify installation
mvar --version
# Expected: MVAR — MIRRA Verified Agent Runtime Version 1.5.3

# Initialize for Claude Code
mvar init --framework claude-code

# Load environment variables written by installer
source ./.mvar.env
```

**Expected output:**
```
✅ MVAR configured for Claude Code
✅ PostToolUse hook installed: ./.claude/hooks/mvar_governor_hook.py
✅ QSEAL signing enabled
✅ Mission Control configured (optional)
```

---

## Step 2: Verify Hook Active (1 minute)

```bash
# Verify hook file was created
ls -la ./.claude/hooks/mvar_governor_hook.py

# Verify hook is executable
test -x ./.claude/hooks/mvar_governor_hook.py && echo "✅ Hook is executable" || echo "❌ Hook not executable"

# Verify QSEAL secret was configured
grep -q QSEAL_SECRET ./.mvar.env && echo "✅ QSEAL_SECRET configured" || echo "❌ QSEAL_SECRET missing"
```

**Expected output:**
```
-rwxr-xr-x  1 user  staff  10240 Apr 21 19:00 /path/to/project/.claude/hooks/mvar_governor_hook.py
✅ Hook is executable
✅ QSEAL_SECRET configured
```

---

## Step 3: Launch Claude Code with MVAR Active (1 minute)

```bash
# Start Claude Code (MVAR hook will intercept all tool calls)
claude

# Or if using VS Code extension:
code .
```

**Status check:** MVAR is now monitoring all Bash tool calls made by Claude Code.

---

## Step 4: Trigger Benign Command (Allow) (2 minutes)

In Claude Code, ask:
```
List files in the current directory
```

Claude will execute: `ls -la`

**What happens:**
1. Claude Code calls Bash tool with `ls -la`
2. Command executes
3. MVAR hook audits AFTER execution (PostToolUse)
4. Policy engine evaluates: **ALLOW** (benign read operation)
4. QSEAL signs the decision
5. Signed decision sent to Mission Control (if configured)

**Verify in Claude Code output:**

Claude will show you the command output normally. The hook runs silently in the background, auditing the command and sending the signed decision to Mission Control (if configured).

To see the hook fired, check the Mission Control dashboard at `http://localhost:3000` (if running).

---

## Step 5: Trigger Attack (Audit) (2 minutes)

In Claude Code, ask:
```
Delete all files in /tmp recursively
```

Claude will attempt: `rm -rf /tmp/*`

**What happens:**
1. Claude Code calls Bash tool with `rm -rf /tmp/*`
2. Command **executes** (PostToolUse is audit-only)
3. MVAR hook audits AFTER execution
4. Policy engine evaluates: **WOULD HAVE BLOCKED** (destructive operation)
5. QSEAL signs the audit decision
6. Claude receives: "MVAR Audit: WOULD HAVE BLOCKED (enforcement_mode: observe)"
7. Signed audit decision sent to Mission Control

**Note:** PostToolUse hooks run AFTER execution for audit visibility. The command executes, but violations are logged.

**Verify the audit message:**

Claude Code will display the hook's audit message in its output:
```
🔶 MVAR Audit: WOULD HAVE BLOCKED (enforcement_mode: observe)

Command: rm -rf /tmp/*
Reason: Recursive deletion matched policy rule: destructive_operations
Category: destructive_operations
Severity: critical
Rule: BASH_RM_RF_RECURSIVE

This command was allowed to execute for audit visibility.
```

The signed decision is sent to Mission Control (if configured) and can be viewed in the dashboard.

---

## Step 6: Verify Mission Control Integration (2 minutes)

**If Mission Control is running** (optional), you can verify the signed decision was received:

1. Open Mission Control dashboard: `http://localhost:3000`
2. Navigate to Tasks tab
3. Find the most recent task with tags `mvar`, `policy-outcome`
4. Verify metadata includes:
   - `mvar_policy_outcome` with decision details
   - `qseal_signature` (HMAC-SHA256 signature)
   - `qseal_verified: true` (signature was verified)
   - `clawzero_witness` with command and execution confirmation

**What the signature proves:**
1. The audit decision was made by MVAR (not forged)
2. The decision content hasn't been tampered with (HMAC integrity)
3. The decision is authentic within the trust boundary (shared secret)

**Note:** Current QSEAL mode is HMAC-SHA256 (tamper-evident within trust boundary). For third-party non-repudiation, Ed25519 mode is planned for 1.6.0.

---

## Step 7: Mission Control Dashboard (Optional)

**If Mission Control is running**, the dashboard provides:

- **Real-time policy decisions** - See all agent operations and policy outcomes
- **QSEAL signature verification** - Cryptographic proof of decision authenticity
- **Audit trail export** - Download signed decision history for compliance
- **Violation analytics** - Track "would have blocked" patterns over time

If your Mission Control instance is already running, dashboard is typically available at `http://localhost:3000`.

---

## Success Criteria

After 10 minutes, you should have:

✅ **Installed MVAR** in one command
✅ **Verified hook** is active and configured
✅ **Allowed benign command** to execute (with silent audit)
✅ **Audited attack** after execution (logged "would have blocked")
✅ **Sent signed audit decision** to Mission Control (if configured)
✅ **Verified QSEAL signature** in Mission Control metadata

---

## What This Proves

1. **Installation works:** One command, no manual configuration
2. **Audit works:** Policy evaluates all operations and logs violations
3. **Signing works:** Every decision is cryptographically signed with QSEAL
4. **Verification works:** Signatures can be independently verified

**Current Mode: Observe (Audit-Only)**
- Commands execute regardless of policy decision
- Violations are logged as "would have blocked"
- Provides visibility without breaking developer workflow
- Enforcement mode (PreToolUse) requires framework support

**What this doesn't prove (yet):**
- Pre-execution blocking (requires PreToolUse hook support)
- Bypass resistance (requires adversarial testing)
- Scale (single developer, not team deployment)
- Multi-framework support (only Claude Code is GA)

See [GAP_CLOSURE_TRACKER.md](GAP_CLOSURE_TRACKER.md) for planned improvements.

---

## Troubleshooting

### Hook not firing

```bash
# Check hook is installed
ls -la ./.claude/hooks/mvar_governor_hook.py

# Check hook is executable
chmod +x ./.claude/hooks/mvar_governor_hook.py

# Check local Claude settings configuration
cat ./.claude/settings.local.json | grep -A 3 PostToolUse
```

### QSEAL_SECRET not found

```bash
# Check environment file exists
cat ./.mvar.env

# Regenerate if missing (will prompt to overwrite existing hook)
mvar init --framework claude-code
```

### No decisions logged

```bash
# Enable hook debug logging and inspect audit log
export MVAR_HOOK_DEBUG=1
tail -f /tmp/mvar_hook_mc_debug.log
```

---

## Next Steps

- [Review Framework Support](SUPPORT_MATRIX.md) - See which frameworks are production-ready
- [Understand Security Profiles](SECURITY_PROFILES.md) - Policy configuration options
- [Read Agent Integration Guide](AGENT_INTEGRATION_PLAYBOOK.md) - Integrate MVAR with your agent
- [Review Evaluation Protocol](security/EVALUATION_PROTOCOL.md) - Adversarial testing methodology

---

**Questions?** https://github.com/mvar-security/mvar/discussions
