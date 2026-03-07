# MVAR Public Schemas

This directory defines the public, versioned schemas for MVAR's execution-boundary contract.

## Versioning

MVAR uses Kubernetes-style API versioning:

- **v1**: Stable, production-ready, guaranteed backward compatibility
- **v1beta1**: Feature-complete, testing in production, may have minor breaking changes
- **v2alpha1**: Early development, unstable, may change significantly

## Stability Guarantees

### v1 Schemas

Once a schema reaches `v1`, it is **stable**. Changes to v1 schemas must be:

1. **Backward compatible** (new optional fields only)
2. **Additive** (never remove or rename fields)
3. **Documented** in CHANGELOG.md with migration guides

Breaking changes require a new API version (v2, v3, etc.).

### Integration Surface

These schemas define the contract between:

- **Input**: `ExecutionIntent` — What the agent wants to do
- **Output**: `DecisionRecord` — MVAR's policy decision

All MVAR integrations (agent adapters, policy engines, audit systems) must conform to these schemas.

## Usage

### Validation

```python
import jsonschema
import json

with open("spec/execution_intent/v1.schema.json") as f:
    schema = json.load(f)

intent = {
    "apiVersion": "mvar.io/v1",
    "kind": "ExecutionIntent",
    # ... rest of intent
}

jsonschema.validate(intent, schema)
```

### Extending

To add custom fields:

1. Use `x-*` prefix for vendor-specific extensions
2. Do not rely on extension fields for core policy logic
3. Extensions are not guaranteed to be preserved across MVAR versions

## Migration Policy

### Adding New Fields to v1

New optional fields can be added to v1 schemas if:

1. Field is optional (not required)
2. Default behavior is unchanged if field is absent
3. Change is documented in CHANGELOG.md

### Breaking Changes

Breaking changes require a new API version:

- Renaming fields → v2
- Removing fields → v2
- Changing field types → v2
- Making optional fields required → v2

### Deprecation Policy

When v2 is released:

1. v1 remains supported for **12 months minimum**
2. Deprecation warnings added to v1 documentation
3. Migration guide published with v2 release notes
4. Both versions accepted during transition period

## Examples

See `examples/` subdirectories for real-world intent and decision payloads
covering the full decision matrix: ALLOW, BLOCK, and STEP_UP outcomes.
