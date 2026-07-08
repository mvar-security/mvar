# MVAR Implementation Phases - Planning Document

**Status**: Planning only - not yet implemented
**Purpose**: Break down the two-directive approach into clear, sequential phases
**Context**: ChatGPT, Claude, and Codex all converged on: spec first, wrapper second

---

## Why Two Phases?

**The Problem**: Trying to implement both the public spec AND the wrapper simultaneously creates:
1. Unclear success criteria (what's "done"?)
2. Mixed concerns (contract design vs. runtime implementation)
3. Risk of spec changing mid-implementation

**The Solution**: Split into two directives with clear boundaries:

- **Phase 1: Spec-Only** - Define the contract (ExecutionIntent + DecisionRecord schemas)
- **Phase 2: Wrapper Implementation** - Build the `protect(agent)` runtime

Each phase has:
- Clear deliverables
- Testable success criteria
- No dependencies on the other phase completing first (can parallelize if needed)

---

## Phase 1: Public Spec Schemas (Contract Design)

**Goal**: Create versioned, stable JSON Schema definitions for MVAR's execution boundary contract.

**Deliverables**:

1. **`spec/` directory structure**
   ```
   spec/
   ├── README.md
   ├── execution_intent/
   │   ├── v1.schema.json
   │   └── examples/
   │       ├── shell_execution.json
   │       ├── file_read.json
   │       ├── api_call_untrusted.json
   │       └── tainted_write.json
   └── decision_record/
       ├── v1.schema.json
       └── examples/
           ├── allow.json
           ├── block.json
           └── step_up.json
   ```

2. **JSON Schema Draft 2020-12 compliant schemas**
   - `execution_intent/v1.schema.json` - Input contract
   - `decision_record/v1.schema.json` - Output contract

3. **Example payloads** - At least 4 ExecutionIntent + 3 DecisionRecord examples

4. **Validation tooling** - Script to validate all examples against schemas

5. **Documentation** - `spec/README.md` explaining versioning and stability guarantees

**Success Criteria**:

✅ All example payloads validate against their schemas using `check-jsonschema`
✅ Schemas include all required fields from planning doc
✅ Examples cover: BLOCK case, ALLOW case, STEP_UP case
✅ `spec/README.md` documents versioning policy and migration path
✅ No breaking changes possible to v1 without bumping to v2

**Timeline**: 1-2 days

**Dependencies**: None (can start immediately)

**Testing**:

```bash
# Validate all examples
check-jsonschema --schemafile spec/execution_intent/v1.schema.json \
  spec/execution_intent/examples/*.json

check-jsonschema --schemafile spec/decision_record/v1.schema.json \
  spec/decision_record/examples/*.json
```

**Git Commit Message** (when implemented):
```
Add public spec schemas for MVAR v1 contract

- ExecutionIntent v1 schema (input to policy evaluation)
- DecisionRecord v1 schema (output of policy evaluation)
- 7 example payloads covering BLOCK/ALLOW/STEP_UP cases
- Versioning policy documented in spec/README.md

This establishes the stable public contract for MVAR integrations.
All agent adapters, policy engines, and audit systems must conform
to these schemas.

Schemas use JSON Schema Draft 2020-12 standard.
Validation: check-jsonschema (all examples pass)

Ref: PLANNING_SPEC_SCHEMAS.md
```

**Not included in Phase 1** (explicitly deferred):
- No Python code (only JSON Schema + examples)
- No runtime validation logic (schemas define contract, not enforce it yet)
- No policy engine implementation
- No wrapper implementation

---

## Phase 2: protect(agent) Wrapper (Runtime Implementation)

**Goal**: Implement one-line `protect(agent)` wrapper with zero-config security.

**Prerequisites** (must complete before starting):

1. **Package structure inspection**
   - Confirm actual import path: `from mvar import protect` or `from mvar_core import protect`?
   - Identify where `mvar/protect.py` (or `mvar_core/protect.py`) should live
   - Check existing module structure to avoid conflicts

2. **Phase 1 complete** (optional but recommended)
   - Schemas exist to generate ExecutionIntent/DecisionRecord payloads
   - If Phase 1 not done, wrapper will use dict payloads instead of validated schemas

**Deliverables**:

1. **Core wrapper module** - `mvar/protect.py` (or appropriate path)
   ```python
   from mvar import protect

   def protect(
       agent,
       profile: str = "balanced",
       policy: dict | None = None,
       audit: bool = True,
       on_block: Callable | None = None,
       framework: str | None = None,
   ) -> agent:
       # Implementation
   ```

2. **Security profiles** - `mvar/profiles.py`
   ```python
   PROFILES = {
       "strict": {...},
       "balanced": {...},
       "permissive": {...},
   }
   ```

3. **Framework adapters** (v1 supports 4 frameworks)
   - `mvar/adapters/langchain_adapter.py`
   - `mvar/adapters/openai_adapter.py`
   - `mvar/adapters/autogen_adapter.py`
   - `mvar/adapters/crewai_adapter.py`

4. **Auto-detection logic** - `mvar/detect.py`
   ```python
   def detect_framework(agent) -> str:
       # Returns "langchain" | "openai" | "autogen" | "crewai"
   ```

5. **Exception classes** - `mvar/exceptions.py`
   ```python
   class MVARPolicyViolation(Exception):
       def __init__(self, reason: str, decision: DecisionRecord):
           # ...
   ```

6. **Tests** (minimum 50 tests)
   - Unit tests: `tests/test_protect.py`
   - Integration tests: `tests/test_langchain_integration.py`, etc.
   - Framework-specific tests: `tests/adapters/test_langchain_adapter.py`, etc.

7. **Documentation updates**
   - Update main README.md with "Quick Start" section showing `protect(agent)`
   - Add `docs/WRAPPER_API.md` with full API reference
   - Add examples to `examples/protect_*.py`

**Success Criteria**:

✅ Zero-config works: `protect(agent)` with no params blocks UNTRUSTED + CRITICAL
✅ Auto-detection works for all 4 frameworks (LangChain, OpenAI, AutoGen, CrewAI)
✅ Protected agent has identical interface to original agent
✅ All 3 profiles (strict, balanced, permissive) behave as documented
✅ `MVARPolicyViolation` raised on BLOCK with full DecisionRecord
✅ 50+ tests pass covering all frameworks × profiles × provenance combinations
✅ Performance: < 5ms p99 policy evaluation latency (measured in tests)

**Timeline**: 1-2 weeks (depends on framework complexity)

**Dependencies**:
- Package structure inspection (2-hour task, prerequisite)
- Existing MVAR core policy engine (assumed to exist in `mvar-core/`)

**Testing Strategy**:

```python
# Unit test example
def test_protect_langchain_balanced_blocks_untrusted_critical():
    from langchain.agents import Agent, Tool
    from mvar import protect, MVARPolicyViolation

    agent = Agent(tools=[Tool(name="bash", func=os.system)])
    protected = protect(agent, profile="balanced")

    with pytest.raises(MVARPolicyViolation) as exc:
        protected.run("Delete /etc/passwd")

    assert exc.value.decision.outcome == "BLOCK"
    assert exc.value.decision.integrity == "UNTRUSTED"
    assert exc.value.decision.sinkLevel == "CRITICAL"

# Integration test example
def test_end_to_end_protection():
    # Full LangChain agent with multiple tools
    # Attempt safe + unsafe operations
    # Verify correct blocking behavior
    pass
```

**Git Commit Message** (when implemented):
```
Add protect(agent) one-line wrapper for MVAR

- Zero-config security: protect(agent) blocks UNTRUSTED + CRITICAL
- Auto-detects 4 frameworks: LangChain, OpenAI, AutoGen, CrewAI
- 3 security profiles: strict, balanced (default), permissive
- Custom policy support via dict parameter
- on_block callback for SIEM/alerting integration

Usage:
    from mvar import protect
    agent = protect(agent)  # That's it.

Interface preservation: protected agent has identical API to original.
Performance: < 5ms p99 policy evaluation latency.

Tests: 50+ unit + integration tests (all passing)
Frameworks tested: LangChain 0.1.x, OpenAI 1.x, AutoGen 0.2.x, CrewAI 0.x

Ref: PLANNING_PROTECT_WRAPPER.md
```

**Not included in Phase 2** (explicitly deferred):
- Admission controller API (Phase 3)
- Policy bundle format (Phase 3)
- Web UI for policy management (future)
- Multi-language support (Python only in v1)

---

## Phase 1 + Phase 2: How They Connect

**Independent but complementary**:

- **Phase 1** defines the contract (schemas)
- **Phase 2** uses the contract (runtime enforcement)

**If Phase 1 completes first**:
- Phase 2 can import schemas and validate payloads: `jsonschema.validate(intent, EXECUTION_INTENT_V1_SCHEMA)`
- Phase 2 can reference examples from `spec/examples/` in tests

**If Phase 2 completes first**:
- Phase 2 uses plain dicts for ExecutionIntent/DecisionRecord
- When Phase 1 completes, add validation layer: `validate_intent(intent_dict)`

**Ideal flow** (recommended):
1. Start Phase 1 (2 days)
2. While Phase 1 is in review, start package structure inspection for Phase 2 (2 hours)
3. Complete Phase 1 merge
4. Start Phase 2 using schemas from Phase 1 (1-2 weeks)
5. Complete Phase 2 merge

---

## What Happens After Phase 2?

**Phase 3: Admission Controllers + Extensibility** (future, not in current scope)

Based on Codex's 5-step reflection, the next phases would be:

1. **Admission Controller API** - Allow custom pre-execution hooks
2. **Policy Bundle Format** - Distributable policy packages
3. **Decision Log Spec** - Standardized audit format for SIEM integration
4. **Reference Integration** - Polished example showing MVAR in production app

**Not planning these yet** - Phase 1 + Phase 2 are sufficient for v1.0 launch.

---

## Directive Splitting: Which Goes to Codex?

### Directive 1 for Codex: Spec-Only

**Scope**: Implement Phase 1 only (spec/ directory + schemas + examples)

**Input**: `PLANNING_SPEC_SCHEMAS.md`

**Output**:
- `spec/` directory with all files
- Validation passing
- Git commit ready for PR

**Command**:
```
Implement Phase 1 from PLANNING_SPEC_SCHEMAS.md:
- Create spec/ directory structure
- Implement ExecutionIntent v1.schema.json
- Implement DecisionRecord v1.schema.json
- Add 7 example payloads
- Add spec/README.md
- Validate all examples with check-jsonschema
- Commit with message from planning doc
```

### Directive 2 for Codex: Wrapper Implementation

**Scope**: Implement Phase 2 only (protect(agent) wrapper)

**Prerequisites**:
1. Run package structure inspection first
2. Confirm import path
3. Identify where files should live

**Input**: `PLANNING_PROTECT_WRAPPER.md` + package inspection results

**Output**:
- `mvar/protect.py` (or appropriate path)
- `mvar/profiles.py`
- `mvar/adapters/` with 4 framework adapters
- 50+ tests
- Documentation updates
- Git commit ready for PR

**Command** (AFTER package inspection):
```
Implement Phase 2 from PLANNING_PROTECT_WRAPPER.md:
- Package root confirmed as: [RESULT OF INSPECTION]
- Create protect() function in [CONFIRMED PATH]/protect.py
- Implement 3 security profiles
- Implement 4 framework adapters (LangChain, OpenAI, AutoGen, CrewAI)
- Write 50+ tests covering all matrix combinations
- Update README.md with Quick Start
- Commit with message from planning doc
```

---

## Package Structure Inspection (2-Hour Task Before Phase 2)

**Why needed**: Cannot write `protect(agent)` without knowing:
1. Is package root `mvar/` or `mvar_core/` or `mvar_runtime/`?
2. Where does `protect.py` file live?
3. What's the import path users will use?

**Tasks**:
1. Read `setup.py` or `pyproject.toml` to find package name
2. Check existing module structure:
   ```bash
   find mvar* -type f -name "*.py" | head -20
   ```
3. Identify if there's already a top-level `__init__.py`:
   ```bash
   cat mvar/__init__.py  # or mvar_core/__init__.py
   ```
4. Confirm import path works:
   ```python
   # Test in Python REPL
   import mvar  # or import mvar_core
   print(mvar.__file__)
   ```

**Output**: Confirmation of:
- Package root: `mvar/` (most likely based on repo name)
- Import path: `from mvar import protect`
- File location: `mvar/protect.py`

**Directive for this task**:
```
Inspect the mvar package structure and confirm:
1. Package root directory (mvar/ or mvar_core/ or other?)
2. Current __init__.py contents
3. Existing module structure
4. What import path should users use?

Output a summary:
- Package root: [path]
- Import statement: from [package] import protect
- File location for protect.py: [path]
- Any conflicts with existing modules: [yes/no, details]
```

---

## Risk Mitigation

### Risk 1: Spec changes during wrapper implementation

**Mitigation**: Complete Phase 1 and merge before starting Phase 2 implementation.

### Risk 2: Framework adapter complexity underestimated

**Mitigation**: Start with LangChain only in Phase 2 MVP, add other frameworks incrementally.

**Revised Phase 2 timeline if this happens**:
- Week 1: LangChain adapter + core wrapper
- Week 2: OpenAI + AutoGen adapters
- Week 3: CrewAI adapter + performance optimization

### Risk 3: Performance target (< 5ms) not achievable

**Mitigation**: Add caching layer for policy decisions, make audit logging async.

If still not achievable: Revise target to < 10ms and document in README as known limitation.

### Risk 4: Package structure inspection reveals conflicts

**Mitigation**: If `mvar/protect.py` conflicts with existing module, use alternative:
- Option A: `mvar/wrapper.py` with `from mvar.wrapper import protect`
- Option B: `mvar/runtime/protect.py` with `from mvar.runtime import protect`

---

## Summary: Two Clean Directives

| Aspect | Phase 1: Spec | Phase 2: Wrapper |
|--------|---------------|------------------|
| **Input** | PLANNING_SPEC_SCHEMAS.md | PLANNING_PROTECT_WRAPPER.md + inspection results |
| **Scope** | JSON Schemas + examples | Python runtime code + tests |
| **Timeline** | 1-2 days | 1-2 weeks |
| **Dependencies** | None | Package inspection (2 hours) |
| **Success** | All examples validate | 50+ tests pass, < 5ms latency |
| **Output** | spec/ directory | mvar/protect.py + adapters/ + tests/ |
| **Parallelizable?** | Yes (can start immediately) | Only after inspection |

**Recommended order**:
1. Phase 1 (Codex Directive 1) - Start now
2. Package inspection (2 hours) - Can overlap with Phase 1 review
3. Phase 2 (Codex Directive 2) - Start after inspection complete

---

**Next Step**: Review all three planning docs, confirm approach, then send Directive 1 to Codex.
