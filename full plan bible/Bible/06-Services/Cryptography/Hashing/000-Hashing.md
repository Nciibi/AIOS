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

Constant-time comparison prevents timing side-channel attacks. Verification never reveals the computed hash on failure; only the boolean result is returned.

### Hash Stream Flow

```
1. Entity calls CSP.hashStream(stream, algorithm)
2. CSP initializes hash context for algorithm
3. CSP reads stream in 64KB chunks
4. CSP updates hash context with each chunk
5. On stream end: CSP finalizes hash, returns digest
6. On stream error: CSP discards context, returns error
```

Stream hashing is used for large files (Genome templates, evidence packages) where loading the entire payload into memory is undesirable.

### Algorithm Selection

For hashing, CSP applies these selection rules:
1. Entity requests specific algorithm → use it (if entity capability permits)
2. Entity requests default → use SHA-256
3. Entity requested algorithm deprecated → CSP selects next available in capability
4. Entity has no hash capability → reject operation

## Hash Operation Error Codes

| Error Code | Condition | Recovery |
|-----------|-----------|----------|
| HSH_001 | Unsupported algorithm requested | Call getSupportedHashAlgorithms |
| HSH_002 | Algorithm deprecated/blocked | Use active alternative |
| HSH_003 | Hash verification mismatch | Data or expected hash corrupted |
| HSH_004 | Stream read error during hashStream | Retry with valid stream |
| HSH_005 | Output buffer too large (>1GB) | Reduce input size |

## Algorithm Lifecycle

```
Proposed → Active → Deprecated → Blocked
```

| State | Description | Action |
|-------|-------------|--------|
| Proposed | Under evaluation for introduction | No operations |
| Active | Fully supported | All operations allowed |
| Deprecated | Still functional, replacement recommended | Operations allowed, warning logged |
| Blocked | Disabled by CSP | No operations, explicit error |

Algorithm deprecation timeline:
1. Announce deprecation 6 months before blocking
2. Auto-route to replacement algorithm during transition
3. Block date: algorithm produces CSP_ERR_002 for any operation
4. Blocked algorithms may be re-enabled by Security Council order only

## Event Chain Hashing

Events in the Event Store are linked through SHA-384 hashes. Each event block contains:

| Field | Description |
|-------|-------------|
| previous_hash | SHA-384 of previous event block |
| event_data | Serialized event payload |
| block_hash | SHA-384 of (previous_hash + event_data) |

This creates an immutable chain: tampering with any event changes its hash, which breaks the chain link to all subsequent events.

## Hashing Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Hashing.HashCompleted | Hash operation completes | algorithm, input_size_bytes, entity_id |
| Hashing.VerificationSuccess | Hash verification matches | algorithm, entity_id |
| Hashing.VerificationFailure | Hash verification fails | algorithm, entity_id |
| Hashing.StreamCompleted | Stream hash completes | algorithm, total_bytes, chunks |
| Hashing.AlgorithmDeprecated | Algorithm transitions to deprecated | algorithm, replacement, deprecation_date |
| Hashing.AlgorithmBlocked | Algorithm blocked | algorithm, reason |

## Cross-Cutting Concerns

### Security
Deprecated algorithms are blocked at the CSP boundary. Hash verification uses constant-time comparison to prevent timing side-channels. Hash results are authenticated through the Event Store chain. Pre-image and collision resistance requirements are enforced by algorithm selection.

### Evidence
Every hash operation produces a Hashing event. Verification failures are logged with algorithm identifier (hash value is not logged). Stream hashing logs total bytes processed for audit.

### Lifecycle
Algorithms progress: proposed → active → deprecated → blocked. Algorithm deprecation is announced 6 months before blocking. Transition to blocked requires Security Council order.

### Capability Bounds
Entities may only use hash algorithms their capability profile permits. Default algorithm is SHA-256 for all entities unless overridden. A constrained entity may be restricted to SHA-256 only.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Hashing is a single concern: produce/verify digests. |
| R3 | Algorithm specifications defined in one place (this document). |
| R9 | Hashing is deterministic: same input, same output. |
| R10 | Single hash call, single comparison. No branching. |
| R12 | Every error has a unique code (HSH_001-005). |
| R13 | Hash algorithm unavailable → CSP selects next available in capability. |
| R14 | Paved path: hash → verify. No alternative hashing paths. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-CSP.md | CSP executes all hashing operations |
| Physics/005-Events.md | Event chain integrity uses SHA-384 hashing |
| Certificates/000-Certificates.md | Certificate fingerprints use SHA-256 |
| Signatures/000-Signatures.md | Signatures operate on hashes, not plaintext |
| Core/AGS/* | Genome signing uses SHA-256 hashing |
