# AIOS Bible — Cryptography
## Random / 000 — Cryptographic Random Number Generation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services / Cryptography |
| Document ID | AIOS-BBL-006-RND-000 |
| Source Laws | Law 4 — Evidence, Law 8 — Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document specifies cryptographic random number generation for AIOS. All randomness with security implications uses hardware-backed entropy. CSP provides three tiers of RNG: hardware RNG (HSM), OS entropy pool, and CSPRNG for non-cryptographic uses.

## RNG Sources

| Source | Entropy Quality | Use Case | Availability |
|--------|----------------|----------|--------------|
| HSM Hardware RNG | Maximum (true hardware entropy) | Key generation, nonces, IVs | HSM required |
| CPU RDRAND | High (hardware digital random) | Fallback for HSM unavailability | Most modern CPUs |
| OS Entropy Pool | High (kernel entropy collection) | General cryptographic randomness | Always |
| CSPRNG (seeded) | Medium (deterministic from seed) | Session IDs, jitter, shuffle | Always |

## RNG Quality Hierarchy

```
HSM RNG ──► CPU RDRAND ──► OS Entropy Pool ──► CSPRNG
(optimal)    (backup)       (standard)          (non-crypto only)
```

CSP selects the best available source in order:
1. If HSM available: use HSM hardware RNG for all cryptographic operations
2. If HSM unavailable: use CPU RDRAND + OS entropy pool
3. For non-cryptographic randomness only: use CSPRNG

## Operations

| Operation | Description | Parameters | RNG Source |
|-----------|-------------|------------|------------|
| getRandomBytes | Generate random bytes | count: uint | HSM / RDRAND / OS |
| getRandomInt | Random integer in range | min: int, max: int | HSM / RDRAND / OS |
| getRandomUUID | Generate UUID v4 | — | HSM / RDRAND / OS |
| shuffle | Fisher-Yates shuffle | array: T[] | CSPRNG (non-crypto) |

### getRandomUUID

UUIDs follow RFC 4122 v4 (random). Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` where x is random and y is the variant bits (10xx). UUIDs are generated from HSM or OS entropy, never from CSPRNG.

## Entropy Monitoring

CSP monitors entropy levels continuously and alerts the Security Council if entropy drops below threshold.

| Metric | Threshold | Alert Severity | Action |
|--------|-----------|----------------|--------|
| HSM Entropy | < 0.5 bits/byte | Critical | Failover to OS entropy, alert Security Council |
| OS Entropy | < 100 bits available | Warning | Log, use CPU RDRAND |
| CPU RDRAND | Status check fails | Warning | Disable RDRAND, use OS entropy only |
| CSPRNG Seed | Seed > 24 hours old | Warning | Re-seed from OS entropy |

## Non-Cryptographic Randomness

For non-cryptographic purposes (session IDs for routing, jitter for retry backoff, shuffle for load balancing), CSP uses a CSPRNG seeded from the OS entropy pool. The CSPRNG is re-seeded every hour.

Non-cryptographic randomness is explicitly flagged as such in the operation response. Callers must not use non-cryptographic randomness for security-sensitive operations.

## Cross-Cutting Concerns

### Security
All cryptographic random data comes from HSM or OS entropy. CSPRNG is never used for key generation, nonces, IVs, or any operation with security implications. RNG source selection is deterministic based on availability.

### Evidence
Random generation operations are logged with source identifier. Entropy warnings are escalated to Security Council. Entropy depletion events are stored in the Event Store.

### Lifecycle
RNG sources have a health lifecycle: healthy → degraded → failed. CSP monitors all sources and fails over automatically.

### Capability Bounds
Entities may specify minimum RNG quality requirements. A key generation operation may require HSM RNG; CSP enforces this.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R9 | Randomness is the only non-deterministic operation. All other CSP ops are deterministic. |
| R10 | Simple hierarchy: HSM → OS → CSPRNG. No complex selection logic. |
| R13 | All RNG sources have fallbacks. HSM failure → OS entropy. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-CSP.md | CSP provides getRandomBytes and getRandomUUID operations |
| HSM/000-HSM.md | HSM hardware RNG is the preferred entropy source |
| KMS/000-KMS.md | Key generation requires cryptographic randomness from HSM/OS |
| Signatures/000-Signatures.md | Nonce generation for signatures uses getRandomBytes |
| Encryption/000-Encryption.md | IV generation uses getRandomBytes |
