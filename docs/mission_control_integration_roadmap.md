# Mission Control Integration Roadmap (mvar-security)

Status: Execution plan

Window: 4 weeks

Objective: Deliver a production-credible Mission Control integration for MVAR + ClawZero + ClawSeal with verifiable policy and memory integrity telemetry.

## Phase 1 (Week 1): MVP Adapter

Goal: Emit signed policy telemetry into a running Mission Control instance.

Scope:
- Implement `FrameworkAdapter`-style integration layer using the contract in `docs/mission_control_adapter_spec.md`.
- Emit `task.policy_outcome` envelopes with required `qseal` signing.
- Include continuity fields on task events:
  - `continuity_hash`
  - `protocol_version`
  - `constitutional_classification`
- Add witness reference emission (`witness_ref`, `witness_sha256`, `storage`).

Deliverables:
- `mvar_adapters/mission_control.py` (or equivalent runtime path)
- `examples/adapters/mission_control_quickstart.py`
- Contract tests:
  - envelope schema validation
  - QSEAL signature verify pass/fail
  - compatibility-shim downgrade paths
- Demo evidence: screenshot/log export showing event ingestion in Mission Control.

Exit criteria:
- Events visible in Mission Control for register/heartbeat/task lifecycle.
- `task.policy_outcome` emitted and verified end-to-end.

## Phase 2 (Week 2): ClawSeal Panel

Goal: Surface cryptographic memory state directly in Mission Control UI.

Scope:
- Contribute a dashboard panel for ClawSeal scroll verification status.
- Show per-task and per-agent memory integrity indicators:
  - scroll signature validity
  - chain-link validity
  - tamper detection failures
- Join Mission Control Ed25519 audit receipts with ClawSeal QSEAL signatures for end-to-end audit traceability.

Deliverables:
- Panel/component contribution in Mission Control-compatible format.
- Adapter-side API/feed endpoint for panel data.
- UX copy for verification states (`verified`, `degraded`, `tampered`).
- Integration test proving panel reflects real verification outcomes.

Exit criteria:
- UI panel renders live status from adapter output.
- One tamper event is detected and visualized correctly.

## Phase 3 (Week 3): Head-to-Head Demo

Goal: Publish proof-oriented comparison in Mission Control environment.

Scope:
- Build and run three tests:
  - tamper test
  - prompt injection test
  - policy drift test
- Execute baseline vs mvar-security integration runs.
- Capture measurable outcomes (detection, block/allow, trace quality, witness verification).

Deliverables:
- Repro harness scripts and fixed inputs.
- Result artifacts (JSON + screenshots + logs).
- Public write-up + 10-minute video walkthrough.
- One technical post (README section, blog post, or HN-ready technical comment).

Exit criteria:
- Reproducible artifacts for all 3 tests.
- Published report with methods, data, and limitations.

## Phase 4 (Week 4): Upstream Contribution

Goal: Land MVAR adapter upstream as a first-class Mission Control integration.

Scope:
- Package `MVARAdapter` for upstream inclusion.
- Align with Mission Control contribution and release conventions.
- Resolve compatibility review feedback from maintainers.

Deliverables:
- PR: built-in `MVARAdapter` alongside OpenClaw/CrewAI/LangGraph/AutoGen adapters.
- Adapter docs in Mission Control repo:
  - install
  - configuration
  - event mapping
  - security model notes
- Version compatibility matrix and maintenance owner mapping.

Exit criteria:
- Upstream PR opened and accepted (or approved pending release train).
- Integration appears in official adapter list and docs.

## Dependencies and Risk Controls

- Alpha API volatility: mitigated by compatibility shim and versioned schema contract.
- Signature interoperability drift: covered by contract tests for both `qseal` and optional `sig_ext`.
- Evidence quality risk: require scripted, replayable test corpus for Phase 3 publication.

## Success Metrics (End of Week 4)

- Mission Control ingests signed mvar-security policy outcomes in production-like runs.
- ClawSeal verification panel demonstrates memory integrity state at runtime.
- Published head-to-head artifacts are reproducible from repo scripts.
- MVARAdapter accepted upstream or in final review with no blocking technical gaps.
