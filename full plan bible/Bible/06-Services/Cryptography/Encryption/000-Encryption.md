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
3. CSP validates: key exists, key enabled, algorithm permitted, context valid
4. CSP generates random DEK via CSP.generateRandom(32)
5. CSP encrypts data with DEK (AES-256-GCM, 96-bit IV)
6. CSP computes GCM authentication tag over ciphertext + AAD
7. CSP wraps DEK with KEK using key_selector algorithm
8. CSP constructs EncryptedPayload { ciphertext, iv, tag, wrapped_dek, key_selector, context }
9. CSP logs Encryption.OperationCompleted event
10. CSP returns EncryptedPayload
```

### Decrypt Flow

```
1. CSP receives decrypt(ciphertext, context)
2. CSP validates: EncryptedPayload structure, context match, timestamp freshness
3. CSP retrieves KEK key_selector from KMS (or HSM)
4. CSP unwraps DEK using KEK
5. CSP decrypts ciphertext with DEK (AES-256-GCM)
6. CSP verifies GCM authentication tag
7. If tag valid: return plaintext, log Encryption.DecryptionSuccess
8. If tag invalid: return error, log Encryption.DecryptionFailure (ciphertext tampered)
```

### Re-Encrypt Flow

```
1. CSP receives reEncrypt(data, old_key, new_key)
2. CSP decrypts data using old_key (decrypt flow)
3. If decryption succeeds: CSP encrypts with new_key (encrypt flow)
4. CSP returns new EncryptedPayload
5. CSP logs Encryption.ReEncryptionCompleted
```

## Encryption Operation Error Codes

| Error Code | Condition | Recovery |
|-----------|-----------|----------|
| ENC_001 | Key selector not found | Use valid key_id |
| ENC_002 | Key disabled or pending deletion | Enable key or use different key |
| ENC_003 | Algorithm not permitted for entity | Use permitted algorithm |
| ENC_004 | Context validation failed | Provide valid entity_id, purpose, timestamp |
| ENC_005 | GCM authentication tag mismatch | Data tampered or wrong key |
| ENC_006 | KEK unavailable (HSM/KMS down) | Retry or use alternative key |
| ENC_007 | Plaintext size exceeds limit | Max 64KB per encrypt operation |

## ChaCha20-Poly1305 Specifics

Used for constrained environments where AES hardware acceleration is unavailable:

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits |
| Nonce size | 96 bits |
| Tag size | 128 bits |
| Max plaintext | 256 GiB |
| Status | Active (mobile/constrained) |

ChaCha20-Poly1305 is the preferred algorithm for:
- Mobile device agents
- IoT/edge instances
- High-throughput logging where AES-GCM overhead is unacceptable

## age Encryption Specifics

age (Actually Good Encryption) is used for file-level encryption:

| Parameter | Value |
|-----------|-------|
| Key type | X25519 identity |
| Encryption | ChaCha20-Poly1305 per stanza |
| Format | age encrypted file format |
| Use case | Evidence export, cold storage, backup |

age supports passphrase-based and identity-based encryption. Both modes use the same underlying ChaCha20-Poly1305 encryption.

## Encryption Context Mismatch Handling

When decryption context does not match encryption context:

1. CSP compares decrypt context with stored context from EncryptedPayload header
2. If entity_id mismatch: log warning, allow if entity has cross-context capability
3. If purpose mismatch: deny, log Encryption.ContextMismatch
4. If timestamp outside grace period (5 minutes): deny, log Encryption.StaleCiphertext

This prevents:
- Ciphertext captured from one context being replayed in another
- Stale ciphertexts from being decrypted after their intended window
- Cross-entity ciphertext sharing without explicit capability

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
| R9 | Encryption is deterministic given same key, IV, and AAD (GCM). |
| R10 | Envelope encryption is simple, well-understood, single pattern. |
| R12 | Every error has a unique code (ENC_001-007). |
| R13 | Decryption failure → authenticated error (no plaintext leak, no partial decryption). |
| R14 | Paved path: envelope encryption for all data at rest. No alternative encryption paths. |

## Encryption Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Encryption.OperationCompleted | Encrypt/decrypt/reEncrypt completes | operation, algorithm, key_selector, entity_id |
| Encryption.DecryptionSuccess | Decrypt succeeds | entity_id, purpose, key_selector |
| Encryption.DecryptionFailure | Decrypt fails (tag mismatch) | entity_id, reason |
| Encryption.ContextMismatch | Decrypt context does not match encrypt context | entity_id, expected_context, received_context |
| Encryption.ReEncryptionCompleted | Re-encrypt under new key | old_key_selector, new_key_selector, entity_id |
| Encryption.KeyRotationTriggered | KMS triggers re-encrypt for key rotation | old_key, new_key, affected_objects |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-CSP.md | CSP executes all encryption operations |
| KMS/000-KMS.md | KEKs managed by KMS, DEKs generated per operation |
| HSM/000-HSM.md | KEK operations routed to HSM for sensitive contexts |
| SMS/000-SMS.md | SMS secrets encrypted under CSP envelope encryption |
