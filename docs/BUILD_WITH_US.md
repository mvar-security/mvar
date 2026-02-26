# Build With Us

## MVAR is Open Source By Design

We welcome contributions that make MVAR better for everyone—while protecting the security invariants that keep it safe.

### What We're Looking For

**Framework Adapters**
- LangChain, OpenAI Agents, AutoGen, CrewAI, MCP integrations
- Help us bring MVAR to the ecosystems where developers already build

**Security Research**
- Attack vector expansion
- Formal verification
- Red-team testing against real-world threats

**Documentation & Examples**
- Integration guides
- Use case examples
- Benchmark comparisons

**Developer Experience**
- Better error messages
- Debugging tools
- Performance profiling

### Non-Negotiable: Security Invariants

All contributions must preserve these boundaries:

1. **Sink enforcement** — No tool can execute without policy evaluation
2. **Execution token boundary** — Token verification at authorization layer
3. **Principal isolation** — Trust state never crosses principals
4. **Adapter conformance** — All adapters pass the conformance harness

If a contribution bypasses these, it won't merge—no matter how useful otherwise.

### How to Contribute

1. **Start with an issue** — Especially for large changes or new features
2. **Pass the CI gate** — All PRs are validated by our launch-gate workflow
3. **Adapter PRs include**:
   - Conformance test results ([conformance/pytest_adapter_harness.py](../conformance/pytest_adapter_harness.py))
   - Compatibility matrix
   - Performance benchmarks
4. **Security PRs include**:
   - Threat model update
   - Attack vector validation
   - Red-team test results

### Why Open Source MVAR?

**More reviewers** → Real flaws found faster
**More integrators** → Use cases we didn't prioritize first
**More credibility** → Claims are inspectable and reproducible

Open source makes MVAR better. Structured governance keeps it secure.

### Get Started

- **GitHub:** https://github.com/mvar-security/mvar
- **Docs:** [README.md](../README.md)
- **Adapter Contract:** [ADAPTER_SPEC.md](ADAPTER_SPEC.md)
- **First-Party Wrappers:** [FIRST_PARTY_ADAPTERS.md](FIRST_PARTY_ADAPTERS.md)
- **Security Policy:** [SECURITY.md](../SECURITY.md)

### Contact

Questions about contributing? Open an issue or email security@mvar.io.

---

*Encourage aggressively. Govern tightly. That's how open source makes MVAR better without diluting its security model.*
