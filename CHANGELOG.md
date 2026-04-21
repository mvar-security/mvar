# Changelog

All notable changes to MVAR are documented here.
Detailed release notes live under `docs/releases/*`.

## [1.5.2] - 2026-04-21 — Security Update (CVE Fix + CLI Scoping)

**⚠️ Critical: Published 1.5.1 package contained cryptography==46.0.5 with 2 CVEs. This release updates to cryptography==46.0.7.**

### Security
- **Updated cryptography dependency to 46.0.7** (fixes CVEs in 46.0.5)

### Fixed
- **CLI scoping:** Removed unimplemented `mvar test` command; limited `--framework` choices to `claude-code` only (others deferred to 1.6.0)
- **Env parser bug:** Fixed `test_hook()` env loader to strip `export ` prefix from `.mvar.env` entries (was parsing `'export KEY'` as the key instead of `'KEY'`)
- **Documentation:** Changed `pip install mvar` → `pip install mvar-security` in `docs/FIRST_PARTY_ADAPTERS.md` and `docs/AGENT_INTEGRATION_PLAYBOOK.md`

### Migration from 1.5.1
```bash
pip install --upgrade mvar-security==1.5.2
```

---

## [1.5.1] - 2026-04-21 — Critical Hotfix (Import Paths, QSEAL Verification, Secret Leakage)

**⚠️ This release fixes critical issues in 1.5.0. Users should upgrade immediately.**

### Fixed (Severe)
- **S1501-01:** Fixed Mission Control package import path (`mvar.mission_control` now correctly exports `MVARAdapter`)
- **S1501-02:** Fixed Mission Control adapter type import path (changed `mvar.adapters.types` → `mvar.mission_control.types`)
- **S1501-03:** Fixed broken `mvar.qseal` exports (added `QSeal`, `QSealSigner`, convenience functions `sign_decision`, `verify_signature`)
- **S1501-04:** Fixed `qseal_verified` flag — now reflects actual HMAC verification instead of hardcoded `True`
- **S1501-05:** Fixed fail-open/fail-closed contract mismatch in PostToolUse hook (audit-mode messaging now accurate)

### Fixed (Important)
- **I1501-01:** Configured `MC_URL` now respected end-to-end (written to `.mvar.env`, read by hook runtime)
- **I1501-02:** Removed secret leakage from installer output and debug logs (secrets no longer printed to stdout; debug logging disabled by default, enable with `MVAR_HOOK_DEBUG=1`)

### Validation
- **11 new regression tests** added under `tests/release_1_5_1/`
- **374 tests passing** (full test suite, zero regressions)
- Critical imports verified in fresh venv

### Migration from 1.5.0
If you installed 1.5.0, upgrade immediately:
```bash
pip install --upgrade mvar-security==1.5.1
```

---

## [1.5.0] - 2026-04-20 — CLI + Hook + Mission Control Integration (YANKED — Use 1.5.1)

⚠️ **YANKED:** This release shipped with correctness and packaging regressions. **Use 1.5.1 instead.**

### What Was Included
- Added `mvar/hooks/` with Bash policy and Claude Code PostToolUse hook runtime
- Added `mvar/adapters/claude_code.py` installer/test/verify flows
- Added `mvar/mission_control/` adapter and typed payloads
- Added `mvar/qseal` convenience wrapper
- Added unified `mvar` CLI entrypoint

### Known Issues (Fixed in 1.5.1)
- Mission Control imports broken by incorrect module paths
- `mvar.qseal` exported symbols not present in `mvar_core.qseal`
- `qseal_verified` was asserted true without verification in emitted metadata
- PostToolUse audit-mode messaging did not match actual fail-open behavior
- Configured `MC_URL` was not respected (hardcoded localhost fallback)
- Secret exposure risk from debug logging and installer output

---

## [1.4.3] - 2026-03-16 — ExecutionGovernor + ClawZero Integration Bridge
- **What's New:** Added ExecutionGovernor with typed `ExecutionDecision` contract and ClawZero integration bridge. Made ExecutionGovernor importable from main module.
- **Security Impact:** Provides unified execution decision surface for governance layer integration. 293 tests passing.
- **Validation Snapshot:** Full integration with ClawZero 0.4.0 validated.
- **Key PRs:** #73 (ExecutionGovernor), #74 (pre-launch polish, cross-linking)

## [1.4.2] - 2026-03-10 — Version Parity Correction
- **What's New:** Aligned package metadata to match PyPI distribution naming (`mvar-security`).
- **Security Impact:** No security changes — packaging correction only.
- **Validation Snapshot:** PyPI publish lane validated, trusted publishing configured.
- **Key PRs:** #62 (publish as mvar-security), #63 (metadata alignment)

## [1.4.1] - 2026-03-10 — PyPI Lane Bring-Up
- **What's New:** Added package check, trusted PyPI publish lane, and canonical run-the-proof operator guide.
- **Security Impact:** Established deterministic PyPI distribution with CI-gated publishing.
- **Validation Snapshot:** Repro proof pack emits deterministic summary. CHANGELOG and CODE_OF_CONDUCT added to root.
- **Key PRs:** #56 (repro proof), #58 (CHANGELOG/COC), #60 (run-the-proof guide), #61 (PyPI lane)

## [1.4.0] - 2026-03-09 — Verified Execution Contracts
- **What’s New:** Required verified execution contracts for privileged sink calls with invocation-hash binding at enforcement time.
- **Security Impact:** Eliminates decision/execution drift for contracted sinks and hardens replay/mutation resistance at the sink boundary.
- **Validation Snapshot:** Launch gate PASS · Attack corpus 50/50 blocked · Full suite 294 passing.
- **Details:** [docs/releases/v1.4.0.md](docs/releases/v1.4.0.md)

## [1.3.1] - 2026-03-09 — HTTP Egress Hardening
- **What’s New:** Added strict-profile default-deny outbound HTTP egress with explicit allowlist control.
- **Security Impact:** Blocks non-allowlisted egress in strict profile and fails closed when strict allowlist requirements are missing.
- **Validation Snapshot:** Launch-gate and attack-corpus checks remained release-blocking for this line.
- **Details:** [docs/releases/UNRELEASED.md](docs/releases/UNRELEASED.md)

## [1.3.0] - 2026-03-08 — Strict-Mode Enterprise Hardening
- **What’s New:** Enforced Ed25519-only strict mode and required signed policy bundles at strict startup.
- **Security Impact:** Removed strict-mode HMAC fallback and anchored strict decisions to authenticated policy roots.
- **Validation Snapshot:** Launch gate PASS · Attack corpus 50/50 blocked · Full suite 293 passing.
- **Details:** [docs/releases/v1.3.0.md](docs/releases/v1.3.0.md)

## [1.2.3] - 2026-03-08 — README Clarity + Stable Launch Gate
- **What’s New:** Tightened conversion-first README flow while preserving reproducible proof and validation paths.
- **Security Impact:** Kept deterministic sink-enforcement posture intact during documentation and launch-surface refactor.
- **Validation Snapshot:** Launch gate PASS with corpus and CI checks green on the release line.
- **Details:** [docs/releases/v1.2.2.md](docs/releases/v1.2.2.md)
