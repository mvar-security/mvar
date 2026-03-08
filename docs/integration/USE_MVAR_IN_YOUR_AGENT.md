# Use MVAR in Your Agent

This page shows two common integration patterns:

- Mode A: direct library integration
- Mode B: framework adapter integration

## Mode A — Library Integration

Direct integration with runtime policy evaluation.

```python
from mvar_core.profiles import SecurityProfile, create_default_runtime
from mvar_core.provenance import provenance_user_input
from mvar_core.sink_policy import PolicyOutcome

graph, policy, _ = create_default_runtime(
    profile=SecurityProfile.BALANCED,
    enable_qseal=True,
)

node = provenance_user_input(graph, "Summarize this doc")
decision = policy.evaluate(
    tool="bash",
    action="exec",
    target="bash",
    provenance_node_id=node.node_id,
    parameters={"command": "echo hello"},
)
if decision.outcome == PolicyOutcome.BLOCK:
    raise RuntimeError(f"Blocked: {decision.reason}")
```

## Mode B — Framework Adapter

Drop-in adapter pattern for existing tool-calling frameworks.

```python
from mvar_core.profiles import SecurityProfile, create_default_runtime
from mvar_adapters import MVAROpenAIAdapter

graph, policy, _ = create_default_runtime(
    profile=SecurityProfile.BALANCED,
    enable_qseal=True,
)
adapter = MVAROpenAIAdapter(policy, graph, strict=True)
result = adapter.execute_tool_call(tool_call, tool_registry, source_text="model output")
```

## More Adapter Guides

For framework-specific quickstarts, see:

- [../FIRST_PARTY_ADAPTERS.md](../FIRST_PARTY_ADAPTERS.md)
- [../ADAPTER_SPEC.md](../ADAPTER_SPEC.md)
- [../AGENT_INTEGRATION_PLAYBOOK.md](../AGENT_INTEGRATION_PLAYBOOK.md)
