# 10-Minute Proof Runbook

**Goal:** Prove MVAR enforces policy, blocks attacks, and produces cryptographically signed evidence.

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
# Expected: MVAR — MIRRA Verified Agent Runtime Version 1.5.2

# Initialize for Claude Code
mvar init --framework claude-code
```

**Expected output:**
```
✅ MVAR configured for Claude Code
✅ PostToolUse hook installed: ~/.claude/hooks/PostToolUse.sh
✅ QSEAL signing enabled
✅ Mission Control configured (optional)

Test the hook: mvar test --framework claude-code
```

---

## Step 2: Verify Hook Active (1 minute)

```bash
# Test that hook is intercepting tool calls
mvar test --framework claude-code
```

**Expected output:**
```
Testing MVAR hook for Claude Code...

Test 1: Hook execution
  ✅ Hook file exists: ~/.claude/hooks/PostToolUse.sh
  ✅ Hook is executable
  ✅ Hook runs without error

Test 2: Policy enforcement
  ✅ Policy engine loaded
  ✅ Test command blocked: rm -rf /

Test 3: QSEAL signing
  ✅ QSEAL_SECRET configured
  ✅ Decision signed successfully
  ✅ Signature verified

All tests passed. MVAR is active and enforcing policy.
```

---

## Step 3: Launch Claude Code with MVAR Active (1 minute)

```bash
# Start Claude Code (MVAR hook will intercept all tool calls)
claude-code

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
2. MVAR hook intercepts before execution
3. Policy engine evaluates: **ALLOW** (benign read operation)
4. QSEAL signs the decision
5. Command executes
6. Signed decision sent to Mission Control (if configured)

**Check the decision log:**
```bash
tail -1 ~/.mvar/decisions.jsonl
```

**Example output:**
```json
{
  "tool_name": "Bash",
  "command": "ls -la",
  "decision": "allow",
  "confidence": 1.0,
  "policy_version": "1.5.2",
  "qseal_signature": "a3f8c9d2e1b4...",
  "timestamp": "2026-04-21T19:15:32Z"
}
```

---

## Step 5: Trigger Attack (Block) (2 minutes)

In Claude Code, ask:
```
Delete all files in /tmp recursively
```

Claude will attempt: `rm -rf /tmp/*`

**What happens:**
1. Claude Code calls Bash tool with `rm -rf /tmp/*`
2. MVAR hook intercepts before execution
3. Policy engine evaluates: **BLOCK** (destructive operation)
4. QSEAL signs the block decision
5. Command **does not execute**
6. Claude receives: "Command blocked by security policy"
7. Signed block decision sent to Mission Control

**Check the block log:**
```bash
tail -1 ~/.mvar/blocks.jsonl
```

**Example output:**
```json
{
  "tool_name": "Bash",
  "command": "rm -rf /tmp/*",
  "decision": "block",
  "reason": "Recursive deletion matched policy rule: destructive_operations",
  "confidence": 1.0,
  "policy_version": "1.5.2",
  "qseal_signature": "b7e9f3c5a2d8...",
  "timestamp": "2026-04-21T19:17:45Z",
  "blocked": true
}
```

---

## Step 6: Verify Cryptographic Signature (2 minutes)

```bash
# Extract last blocked decision
mvar report --last-block > /tmp/blocked_decision.json

# Verify QSEAL signature
mvar verify-witness /tmp/blocked_decision.json
```

**Expected output:**
```
Verifying decision witness...

✅ Signature valid
✅ Timestamp: 2026-04-21T19:17:45Z
✅ Policy version: 1.5.2
✅ Decision hash matches content
✅ Chain continuity verified

Decision authenticity confirmed.

Details:
  Command: rm -rf /tmp/*
  Decision: BLOCK
  Reason: Recursive deletion matched policy rule: destructive_operations
  Confidence: 1.0
  QSEAL signature: b7e9f3c5a2d8...
```

**Proof:** The signature proves:
1. This decision was made by MVAR (not forged)
2. The decision content hasn't been tampered with
3. The decision is linked to prior decisions in the session (chain continuity)

---

## Step 7: Export Signed Artifact (Optional - 1 minute)

```bash
# Export last 10 decisions as signed audit artifact
mvar report --last 10 --format signed-json > audit_artifact.json

# Verify the artifact
mvar verify-witness audit_artifact.json --verbose
```

**Use cases for signed artifacts:**
- Incident investigation (prove what agent attempted)
- Regulatory compliance (SOC2, ISO 27001)
- Legal evidence (non-repudiation with Ed25519 mode)
- External audit (third party can verify signatures)

---

## Success Criteria

After 10 minutes, you should have:

✅ **Installed MVAR** in one command
✅ **Verified enforcement** is active
✅ **Allowed benign command** to execute
✅ **Blocked attack** before execution
✅ **Produced signed artifact** proving the block
✅ **Verified cryptographic signature** of the decision

---

## What This Proves

1. **Installation works:** One command, no manual configuration
2. **Enforcement works:** Policy blocks destructive operations before execution
3. **Audit works:** Every decision is cryptographically signed
4. **Verification works:** Signatures can be independently verified

**What this doesn't prove (yet):**
- Bypass resistance (requires adversarial testing)
- Scale (single developer, not team deployment)
- Multi-framework support (only Claude Code is GA)

See [ROADMAP.md](ROADMAP.md) for planned improvements.

---

## Troubleshooting

### Hook not firing

```bash
# Check hook is installed
ls -la ~/.claude/hooks/PostToolUse.sh

# Check hook is executable
chmod +x ~/.claude/hooks/PostToolUse.sh

# Test hook manually
echo '{"tool":"Bash","command":"ls"}' | ~/.claude/hooks/PostToolUse.sh
```

### QSEAL_SECRET not found

```bash
# Check environment file exists
cat ~/.mvar/.mvar.env

# Regenerate if missing
mvar init --framework claude-code --force
```

### No decisions logged

```bash
# Check log directory exists
ls -la ~/.mvar/

# Check permissions
chmod 700 ~/.mvar/
```

---

## Next Steps

- [Read the Architecture](ARCHITECTURE.md) - Understand how MVAR works
- [Configure Policies](POLICY_CONFIGURATION.md) - Customize enforcement rules
- [Integrate Mission Control](MISSION_CONTROL.md) - Add dashboard visibility
- [Review Security Model](security/THREAT_MODEL.md) - Understand guarantees and limits

---

**Questions?** https://github.com/mvar-security/mvar/discussions
