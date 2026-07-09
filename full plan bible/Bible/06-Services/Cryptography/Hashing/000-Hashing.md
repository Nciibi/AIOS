# AIOS Bible — Cryptography
## Hashing / 000 — Hashing Specification

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services / Cryptography |
| Document ID | AIOS-BBL-006-HSH-000 |
| Source Laws | Law 4 — Evidence, Law 8 — Verification-First |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document specifies the hashing algorithms, use cases, and operational patterns for all cryptographic hashing in AIOS. Hashing is used for identity signatures, event chain integrity, evidence sealing, and content addressing.

## Supported Algorithms

| Algorithm | Output Size | Speed | Security Level | Status |
|-----------|-------------|-------|----------------|--------|
| SHA-256 | 256 bits | Fast | 128 bits (collision) | Default |
| SHA-384 | 384 bits | Moderate | 192 bits (collision) | FIPS Compliant |
| SHA-512 | 512 bits | Moderate | 256 bits (collision) | High Security |
| BLAKE2b | Variable (default 256) | Very Fast | 128 bits (collision) | Performance |
| SHA-3-256 | 256 bits | Moderate | 128 bits (collision) | Future-proof |

## Use Case Mapping

| Use Case | Algorithm | Rationale |
|----------|-----------|-----------|
| Identity Signatures | SHA-256 | Balance of speed and security; standard for identities |
| Event Chain Integrity | SHA-384 | FIPS compliance for audit trails |
| Evidence Sealing | SHA-512 | Maximum security for sealed evidence |
| Content Addressing | BLAKE2b | Performance for content-addressable storage |
| Certificate Fingerprints | SHA-256 | Industry standard for certificate fingerprints |
| Genome Signatures | SHA-256 | Compatibility with AGS template hashing |
| Session Token Binding | SHA-256 | Performance at scale (high volume) |

## Deprecated Algorithms

The following algorithms are explicitly blocked by CSP and produce no result:

| Algorithm | Reason | Blocked Since |
|-----------|--------|---------------|
| MD5 | Collision attacks practical | v1.0 |
| SHA-1 | Collision attacks demonstrated (SHAttered) | v1.0 |
| MD4 | Preimage attacks practical | v1.0 |

## Operations

| Operation | Description | Parameters |
|-----------|-------------|------------|
| hash | Hash data with algorithm | data: bytes, algorithm: HashAlgorithm |
| verifyHash | Verify data matches expected hash | data: bytes, expected_hash: bytes, algorithm: HashAlgorithm |
| hashStream | Hash streaming data | stream: ReadableStream, algorithm: HashAlgorithm |
| getSupportedHashAlgorithms | List available hash algorithms | — |

### Hash Verification Flow

```
1. Entity calls CSP.verifyHash(data, expected_hash, algorithm)
2. CSP computes hash = CSP.hash(data, algorithm)
3. CSP compares hash with expected_hash (constant-time comparison)
4. If match: return true, log Hashing.VerificationSuccess
5. If no match: return false, log Hashing.VerificationFailure
```

Constant-time comparison prevents timing side-channel attacks.

## Event Chain Hashing

Events in the Event Store are linked through SHA-384 hashes. Each event block contains:

| Field | Description |
|-------|-------------|
| previous_hash | SHA-384 of previous event block |
| event_data | Serialized event payload |
| block_hash | SHA-384 of (previous_hash + event_data) |

This creates an immutable chain: tampering with any event changes its hash, which breaks the chain link to all subsequent events.

## Cross-Cutting Concerns

### Security
Deprecated algorithms are blocked at the CSP boundary. Hash verification uses constant-time comparison. Hash results are authenticated through the Event Store chain.

### Evidence
Every hash operation produces a Hashing.Event. Verification failures are logged with the algorithm and expected vs. computed hash prefix.

### Lifecycle
Algorithms progress: proposed → active → deprecated → blocked. Algorithm deprecation is announced 6 months before blocking.

### Capability Bounds
Entities may only use hash algorithms their capability profile permits. Default algorithm is SHA-256 for all entities unless overridden.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Hashing is a single concern: produce/verify digests. |
| R9 | Hashing is deterministic: same input, same output. |
| R10 | Single hash call, single comparison. No branching. |
| R13 | Hash algorithm unavailable → CSP selects next available in capability. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-CSP.md | CSP executes all hashing operations |
| Physics/005-Events.md | Event chain integrity uses SHA-384 hashing |
| Certificates/000-Certificates.md | Certificate fingerprints use SHA-256 |
| Signatures/000-Signatures.md | Signatures operate on hashes, not plaintext |
| Core/AGS/* | Genome signing uses SHA-256 hashing |
