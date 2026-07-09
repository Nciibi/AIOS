# AIOS Bible — Cryptography
## Encryption / 000 — Encryption Specification

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services / Cryptography |
| Document ID | AIOS-BBL-006-ENC-000 |
| Source Laws | Law 4 — Evidence, Law 8 — Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document specifies the encryption algorithms, modes, key sizes, and operational patterns used by CSP for all encryption operations in AIOS. Encryption is used for data at rest, data in transit, and data in use (envelope encryption).

## Supported Algorithms

### Symmetric Encryption

| Algorithm | Mode | Key Size | IV Size | Tag Size | Status |
|-----------|------|----------|---------|----------|--------|
| AES-256-GCM | GCM | 256 bits | 96 bits | 128 bits | Default |
| ChaCha20-Poly1305 | AEAD | 256 bits | 96 bits | 128 bits | Mobile/Constrained |
| AES-256-CBC | CBC | 256 bits | 128 bits | N/A | Legacy (decrypt only) |

### Asymmetric Encryption

| Algorithm | Key Size | Use Case | Status |
|-----------|----------|----------|--------|
| RSA-OAEP | 4096 bits | Legacy key transport | Legacy |
| ECIES | P-256/P-384 | Elliptic curve integrated encryption | Active |
| age | X25519 + ChaCha20-Poly1305 | Modern file encryption | Active |

## Envelope Encryption

Envelope encryption is the standard pattern for encrypting data at rest:

```
Data ──► AES-256-GCM ──► Ciphertext + IV + Tag
         ▲
         │
    Data Encryption Key (DEK)
         │
         ▼
   DEK ──► RSA-OAEP / ECIES ──► Wrapped DEK
            ▲
            │
       Key Encryption Key (KEK) ──► Stored in HSM/KMS
```

### Envelope Format

| Component | Description | Storage |
|-----------|-------------|---------|
| Ciphertext | AES-256-GCM encrypted data | Data store |
| IV | 96-bit initialization vector | Header |
| Auth Tag | 128-bit GCM authentication tag | Header |
| Wrapped DEK | DEK encrypted under KEK | Header |
| Key Selector | KEK identifier | Header |
| Encryption Context | AAD binding context | Header |

## Encryption Context (AAD)

Every encryption includes Additional Authenticated Data that binds the ciphertext to its intended use:

| Context Field | Description | Required |
|---------------|-------------|----------|
| entity_id | Identity of the encrypting entity | Yes |
| purpose | Intended use of the encrypted data | Yes |
| timestamp | Encryption timestamp (ISO 8601) | Yes |
| context_label | Human-readable context identifier | No |

The encryption context prevents ciphertext misuse: a ciphertext encrypted for storage cannot be decrypted in a network context because the context differs.

## Operations

| Operation | Description | Parameters |
|-----------|-------------|------------|
| encrypt | Encrypt data with key selector | data: bytes, key_selector: KeySelector, context: EncryptionContext |
| decrypt | Decrypt ciphertext | ciphertext: EncryptedPayload, context: EncryptionContext |
| reEncrypt | Re-encrypt under new key | data: EncryptedPayload, old_key: KeySelector, new_key: KeySelector |

### Encrypt Flow

```
1. CSP receives encrypt(data, key_selector, context)
2. CSP retrieves KEK from KMS (or HSM for sensitive)
3. CSP generates random DEK via CSP.generateRandom(32)
4. CSP encrypts data with DEK (AES-256-GCM)
5. CSP wraps DEK with KEK
6. CSP constructs EncryptedPayload { ciphertext, iv, tag, wrapped_dek, key_selector, context }
7. CSP logs Encryption.OperationCompleted event
8. CSP returns EncryptedPayload
```

## Cross-Cutting Concerns

### Security
DEKs are ephemeral and exist only in memory during the encryption operation. KEKs never leave KMS/HSM. Encryption context (AAD) prevents ciphertext reuse across contexts.

### Evidence
Every encrypt/decrypt operation is logged. Decryption failures (wrong key, tampered ciphertext, context mismatch) are logged with error codes.

### Lifecycle
Encryption keys follow the KMS lifecycle. Key rotation re-encrypts data under new keys (reEncrypt operation). Deprecated algorithms are blocked for encryption but allowed for decryption of legacy data.

### Capability Bounds
Entities can only encrypt with algorithms their capability profile permits. A constrained device may only be allowed ChaCha20-Poly1305.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Encryption uses exactly one pattern: envelope encryption. |
| R10 | Envelope encryption is simple, well-understood, single pattern. |
| R13 | Decryption failure → authenticated error (no plaintext leak). |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-CSP.md | CSP executes all encryption operations |
| KMS/000-KMS.md | KEKs managed by KMS, DEKs generated per operation |
| HSM/000-HSM.md | KEK operations routed to HSM for sensitive contexts |
| SMS/000-SMS.md | SMS secrets encrypted under CSP envelope encryption |
