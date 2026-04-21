# QSEAL Signature Modes

**QSEAL** (Quantum-Safe Execution Audit Ledger) provides cryptographic signing of policy decisions. Two modes are supported with different trust properties.

## Mode Comparison

| Property | HMAC-SHA256 (Default) | Ed25519 (Strict) |
|----------|----------------------|------------------|
| **Third-party verifiable** | ❌ No | ✅ Yes |
| **Key management** | ✅ Simple (shared secret) | ⚠️ Complex (asymmetric keypair) |
| **Performance** | ✅ Fast (~1μs/sign) | ✅ Fast (~50μs/sign) |
| **Use case** | Internal audit, team visibility | Regulatory compliance, legal evidence |
| **Forgery resistance** | Anyone with secret can forge | Only private key holder can sign |

## HMAC-SHA256 Mode (Default)

**How it works:**
- Shared secret (32-byte key) known to all parties in trust boundary
- Signature computed as `HMAC-SHA256(canonical_json, secret)`
- Verification requires same secret: `hmac.compare_digest(stored_sig, computed_sig)`

**Trust model:**
- ✅ Detects tampering (unauthorized modification)
- ✅ Proves decision authenticity within trust boundary
- ❌ Does NOT prove who signed (any party with secret can forge)

**When to use:**
- Internal incident investigation
- Team policy violation tracking
- Developer debugging and testing
- Environments where all parties trust each other

**Configuration:**
```bash
# Default mode - no configuration needed
export QSEAL_SECRET=$(openssl rand -hex 32)
```

## Ed25519 Mode (Strict)

**How it works:**
- Private key (32-byte) held by signer only
- Public key (32-byte) can be shared with verifiers
- Signature computed with Ed25519 digital signature algorithm
- Verification uses public key only

**Trust model:**
- ✅ Detects tampering (unauthorized modification)
- ✅ Proves decision authenticity to third parties
- ✅ Proves who signed (only private key holder can create valid signature)
- ✅ Non-repudiation (signer cannot deny signing)

**When to use:**
- Regulatory compliance (SOC2, ISO 27001, GDPR)
- External audit requirements
- Legal evidence chain
- Untrusted verification environments

**Configuration:**
```bash
# Generate Ed25519 keypair
mvar init --framework claude-code --qseal-mode ed25519

# This creates:
# ~/.mvar/qseal_private.key  (keep secret!)
# ~/.mvar/qseal_public.key   (share with verifiers)
```

**Verification by third parties:**
```python
from mvar_core.qseal import verify_ed25519_signature

with open("~/.mvar/qseal_public.key", "rb") as f:
    public_key = f.read()

# Load signed decision from audit log
with open("decision.json") as f:
    decision = json.load(f)

verified = verify_ed25519_signature(
    decision["policy_outcome"],
    decision["qseal_signature"],
    public_key
)
print(f"Signature valid: {verified}")  # Third party can verify without private key
```

## Mode Selection Guide

**Choose HMAC-SHA256 if:**
- You control all verification parties
- You need simple key management
- You're debugging or testing
- You trust everyone with access to the secret

**Choose Ed25519 if:**
- You need third-party verification
- You need legal non-repudiation
- You're meeting compliance requirements (SOC2, ISO)
- You're submitting signed evidence to regulators/auditors

## Implementation Status

| Mode | Status | Version |
|------|--------|---------|
| HMAC-SHA256 | ✅ Shipped | 1.5.0+ |
| Ed25519 | 📋 Planned | 1.6.0 (May 2026) |

## Migration Path

When Ed25519 mode ships in 1.6.0, you can migrate without disrupting existing HMAC deployments:

```bash
# Existing HMAC deployments continue working
mvar verify-witness witness.json  # Uses HMAC verification

# New deployments can opt into Ed25519
mvar init --framework claude-code --qseal-mode ed25519
mvar verify-witness witness.json --mode ed25519 --public-key ~/.mvar/qseal_public.key
```

Both modes will be supported indefinitely. No forced migration.

## Technical Details

### HMAC-SHA256 Implementation
```python
import hmac
import hashlib
import json

def sign_hmac(payload: dict, secret: bytes) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    signature = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
    return signature

def verify_hmac(payload: dict, signature: str, secret: bytes) -> bool:
    expected = sign_hmac(payload, secret)
    return hmac.compare_digest(signature, expected)
```

### Ed25519 Implementation (Planned 1.6.0)
```python
from cryptography.hazmat.primitives.asymmetric import ed25519
import json

def sign_ed25519(payload: dict, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    signature = private_key.sign(canonical)
    return signature

def verify_ed25519(payload: dict, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    try:
        public_key.verify(signature, canonical)
        return True
    except Exception:
        return False
```

## See Also

- [QSEAL Architecture](../ARCHITECTURE.md#qseal-cryptographic-signing)
- [Mission Control Integration](MISSION_CONTROL.md)
- [Audit Trail Export](AUDIT_EXPORT.md)
