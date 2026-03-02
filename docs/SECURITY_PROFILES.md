# Security Profiles

MVAR ships with profile presets in `mvar_core.profiles` for secure and repeatable runtime bootstrapping.

## Usage

```python
from mvar_core.profiles import SecurityProfile, create_default_runtime

graph, policy, capability_runtime = create_default_runtime(
    profile=SecurityProfile.BALANCED,
    enable_qseal=True,
)
```

## Profile Matrix

| Control | STRICT | BALANCED | MONITOR |
|---|---|---|---|
| Fail-closed | ✅ | ✅ | ✅ |
| Execution token required | ✅ | ✅ | ❌ |
| One-time execution nonce | ✅ | ✅ | ❌ |
| Persist nonce across restart | ✅ | ❌ | ❌ |
| Composition risk enabled | ✅ | ✅ | ✅ |
| Declassify token required | ✅ | ✅ | ❌ |
| Signed policy bundle required by default | ❌* | ❌ | ❌ |

`*` Strict keeps signed policy-bundle optional by default to avoid accidental local lockout. Production deployments should enable `MVAR_REQUIRE_SIGNED_POLICY_BUNDLE=1` with a generated bundle.

## Recommendations

1. Start with `BALANCED` for integrations.
2. Move to `STRICT` before production launch.
3. Keep `MONITOR` only for observability-first pilots.

## Public-Bind Exposure Guardrail

Profiles do not bypass exposure checks. If a local-model/gateway service is bound to `0.0.0.0`, MVAR expects explicit intent + auth:

- `MVAR_ALLOW_PUBLIC_BIND=1`
- one auth token/key (for example `MVAR_GATEWAY_AUTH_TOKEN` or `OPENCLAW_API_KEY`)

Without both, diagnostics and startup guardrail paths fail closed.
