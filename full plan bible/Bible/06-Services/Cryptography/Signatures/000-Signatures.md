# AIOS Bible — Cryptography
## Signatures / 000 — Digital Signature Specification

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services / Cryptography |
| Document ID | AIOS-BBL-006-SIG-000 |
| Source Laws | Law 4 — Evidence, Law 5 — Identity, Law 8 — Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document specifies digital signature algorithms, operations, and structures used across AIOS. Digital signatures provide non-repudiation, integrity verification, and identity binding for all signed data.

## Supported Algorithms

| Algorithm | Key Size | Security Level | Status | Use Case |
|-----------|----------|----------------|--------|----------|
| ECDSA P-256 | 256-bit | 128 bits | Default | Session tokens, Genome signing |
| ECDSA P-384 | 384-bit | 192 bits | High Security | Certificate signing, federation |
| Ed25519 | 256-bit | 128 bits | Quantum-Resistant | Long-term signatures, evidence sealing |
| RSA-4096 | 4096-bit | 128 bits | Legacy | Legacy compatibility (decrypt only) |

## Signature Structure

Every signature produced by CSP conforms to this structure:

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| algorithm | Algorithm | Signing algorithm used | Yes |
| signing_time | Timestamp | When signature was produced (ISO 8601) | Yes |
| signature_bytes | bytes | Raw signature value | Yes |
| key_id | KeyID | Identifier of signing key | Yes |
| public_key_fingerprint | SHA-256 | Fingerprint of the public key | Yes |

## Operations

| Operation | Description | Parameters |
|-----------|-------------|------------|
| sign | Sign data with key | data: bytes, key_id: KeyID |
| verify | Verify signature against data | signature: bytes, data: bytes, public_key: PublicKey |
| signHash | Sign a pre-computed hash | hash: bytes, key_id: KeyID |
| verifyHash | Verify signature against hash | signature: bytes, hash: bytes, public_key: PublicKey |

### Signing Flow

```
1. Entity calls CSP.sign(data, key_id)
2. CSP retrieves key from KMS (or HSM for sensitive keys)
3. CSP computes hash = CSP.hash(data, SHA-256)
4. CSP signs hash with private key
5. CSP constructs Signature { algorithm, signing_time, signature_bytes, key_id, pub_key_fp }
6. CSP logs Signing.OperationCompleted
7. CSP returns Signature
```

### Verification Flow

```
1. Entity calls CSP.verify(signature, data, public_key)
2. CSP computes hash = CSP.hash(data, SHA-256)
3. CSP verifies hash + public_key against signature_bytes
4. CSP performs additional checks: algorithm match, key_id match, timestamp freshness
5. If valid: return true, log Signing.VerificationSuccess
6. If invalid: return false, log Signing.VerificationFailure with reason
```

## Multi-Signature

Some operations require multiple signers. The multi-signature structure combines individual signatures:

| Field | Type | Description |
|-------|------|-------------|
| signatures[] | Signature[] | Individual signatures from each required signer |
| threshold | uint | Minimum number of valid signatures required |
| signers[] | IdentityID[] | Ordered list of required signers |

### Multi-Signature Requirements

| Operation | Required Signers | Threshold |
|-----------|-----------------|-----------|
| Constitutional Amendment | Sou + Security Council | 2 of 2 |
| Genome Deprecation | AGS Admin + Security Council | 2 of 2 |
| Evidence Seal Break | Security Council (3 of 5) | 3 of 5 |
| Cross-instance Trust | Both instance CAs | 2 of 2 |

## Signature Use Cases

| Use Case | Algorithm | Signer | Verifier |
|----------|-----------|--------|----------|
| Session Token | ECDSA P-256 | ATS | Verification Pipeline |
| Genome | Ed25519 | AGS | Academy / IDS |
| Certificate | ECDSA P-384 | CAM | All services |
| Federation Message | ECDSA P-384 | Instance CA | Peer instance |
| Evidence Seal | Ed25519 | EVS | Audit Service |
| Constitution | Ed25519 | Sou + Security Council | All entities |

## Cross-Cutting Concerns

### Security
Private keys used for signing are stored in HSM for high-security operations (certificate signing, genome signing). Session token signing keys may be stored encrypted under KMS. Multi-signature requires independent verification of each signature.

### Evidence
Every signing and verification operation is logged. Verification failures include the reason (algorithm mismatch, key mismatch, mathematical verification failure).

### Lifecycle
Signing keys follow KMS lifecycle with automatic rotation. Signatures include signing_time to support time-based verification. Expired keys produce signatures that fail verification.

### Capability Bounds
Entities may only use signing algorithms their capability profile permits. Multi-signature operations require all signers to have the required capability.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Signatures are a single concern: produce and verify. |
| R9 | Signing and verification are deterministic (given same key and data). |
| R10 | Single sign flow, single verify flow, no branching. |
| R14 | Paved path: sign → verify. No alternative signing paths. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-CSP.md | CSP executes all signing operations |
| KMS/000-KMS.md | Signing keys managed by KMS |
| HSM/000-HSM.md | High-security signing operations in HSM |
| 001-CAM.md | Certificate signing uses CSP.sign via ECDSA P-384 |
| Encryption/000-Encryption.md | sign then encrypt for secure message format |
| Hashing/000-Hashing.md | CSP signs hashes of data, not raw data |
