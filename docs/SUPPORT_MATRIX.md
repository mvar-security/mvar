# MVAR Framework Support Matrix

**Last Updated:** 2026-04-21

## Production Ready (GA)

| Framework | Status | Install | Verify | Test | Mission Control | Documentation |
|-----------|--------|---------|--------|------|-----------------|---------------|
| **Claude Code** | ✅ GA | `mvar init --framework claude-code` | ✅ | ✅ | ✅ | [Guide](AGENT_INTEGRATION_PLAYBOOK.md) |

**GA Criteria:**
- One-command install works end-to-end
- Hook verification passes
- Test command exercises real enforcement
- Mission Control receives signed decisions
- 10+ integration tests passing
- User documentation complete

## Planned (Not Production Ready)

| Framework | Status | Planned Release | Notes |
|-----------|--------|-----------------|-------|
| LangChain | 🚧 In Development | 1.6.0 (May 2026) | Adapter exists, installer incomplete |
| OpenAI Agents SDK | 📋 Planned | 1.6.0 (May 2026) | High priority - tool calling native |
| MCP (Model Context Protocol) | 📋 Planned | 1.6.0 (May 2026) | Claude ecosystem integration |
| CrewAI | 📋 Planned | 1.7.0 (July 2026) | Lower priority |
| AutoGen | 📋 Planned | 1.7.0 (July 2026) | Lower priority |

## Experimental (Use at Own Risk)

| Framework | Status | Notes |
|-----------|--------|-------|
| Google ADK | ⚠️ Experimental | Stub implementation only, no install path |

---

## What "Production Ready" Means

✅ **You can trust it:**
- Install works without manual intervention
- Hook verification confirms enforcement is active
- Test command proves policy blocks malicious operations
- Integration tests catch regressions

❌ **Not production ready:**
- Requires manual setup
- Hook verification doesn't exist or fails
- No test command to verify enforcement
- No integration test coverage

## Current Recommendation

**For production use:** Only `Claude Code` is GA. 

**For evaluation:** LangChain/OpenAI adapters work but lack install automation. See `mvar_adapters/` for code.

**For contribution:** We welcome PRs to promote frameworks from Planned → GA. See [CONTRIBUTING.md](../CONTRIBUTING.md).
