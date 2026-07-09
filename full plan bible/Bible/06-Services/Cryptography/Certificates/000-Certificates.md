# AIOS Bible — Cryptography
## Certificates / 000 — Certificate Format and Storage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services / Cryptography |
| Document ID | AIOS-BBL-006-CER-000 |
| Source Laws | Law 5 — Identity, Law 8 — Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document defines the certificate format, storage specification, validation rules, and supported profiles for all certificates managed by CAM. All certificates in AIOS conform to this specification.

## Certificate Schema

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| cert_id | UUID v4 | Unique certificate identifier | Yes |
| subject | DistinguishedName | Certificate subject | Yes |
| issuer | DistinguishedName | Issuing CA subject | Yes |
| serial_number | uint64 | Unique serial per CA | Yes |
| not_before | Timestamp | Validity start | Yes |
| not_after | Timestamp | Validity end | Yes |
| public_key | PublicKey | Subject public key | Yes |
| signature_algorithm | Algorithm | Algorithm used for signing | Yes |
| status | CertStatus | Current lifecycle state | Yes |
| purpose | CertPurpose | Intended use | Yes |
| san[] | string[] | Subject Alternative Names | Conditional |
| ca_id | UUID v4 | Issuing CA identifier | Yes |
| fingerprint | SHA-256 | Self-certificate fingerprint | Yes |

## Certificate Storage

Certificates are stored in the encrypted certificate store, accessed exclusively through CAM. Storage details:

| Aspect | Specification |
|--------|--------------|
| Encryption | AES-256-GCM, key managed by KMS (KEK hierarchy) |
| Storage Engine | ACF-backed key-value store with replication |
| Access Control | CAM only; all external access via CAM operations |
| Backup | Encrypted backup to cold storage every 24 hours |
| Retention | 7 years after certificate expiry or revocation |

Private keys are never stored with certificates. Private keys reside in HSM (for CA keys) or are managed by the entity that generated them.

## Certificate Validation

### Chain Validation

```
Root CA (self-signed, in trust store)
    └── Intermediate CA (signed by Root)
            └── Leaf Certificate (signed by Intermediate)
```

Validation proceeds root-to-leaf:
1. Root CA is trusted (in local trust store)
2. Intermediate signature verified against Root CA public key
3. Leaf signature verified against Intermediate CA public key
4. All certificates in chain have Valid status
5. No certificate in chain is expired or revoked

### Validation Checks

| Check | Description | Failure Action |
|-------|-------------|----------------|
| Chain Validation | Build and verify full chain | Deny |
| Expiry Check | not_before < now < not_after | Deny |
| Revocation Check | CRL lookup for all chain certs | Deny if revoked |
| Purpose Check | Certificate purpose matches usage | Deny |
| Fingerprint Check | SHA-256 fingerprint matches stored | Deny |
| SAN Check | Subject matches intended service | Deny |

## Certificate Profiles

### TLS Server Profile
- Key Usage: digitalSignature, keyEncipherment
- Extended Key Usage: serverAuth
- SAN: service DNS names, IP addresses
- Validity: 90 days

### TLS Client Profile
- Key Usage: digitalSignature
- Extended Key Usage: clientAuth
- SAN: entity identity ID
- Validity: 90 days

### Code Signing Profile
- Key Usage: digitalSignature
- Extended Key Usage: codeSigning
- SAN: not required
- Validity: 1 year

### CA Profile (Root/Intermediate)
- Key Usage: keyCertSign, cRLSign
- Basic Constraints: CA:TRUE, pathLenConstraint
- Validity: 5 years (Root), 2 years (Intermediate)
- Root CA key never exported from HSM

## Cross-Cutting Concerns

### Security
Certificate private keys are never stored in the same location as certificates. CA private keys never leave HSM. Certificate store is encrypted at rest and in transit.

### Evidence
Every certificate state change is an Event. Certificate validation failures are logged with full chain information.

### Lifecycle
Certificates follow the lifecycle defined in 001-CAM.md. Validation is performed on every TLS connection, not just at issuance.

### Capability Bounds
Entities may only hold certificates matching their purpose (e.g., a Worker cannot hold a CA certificate).

### Communication
Certificate operations reach CAM through ACF. CRL distribution and OCSP responses flow through ACF event streams. Certificate status change notifications are broadcast via ACF.

## Certificate Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Certificate.Issued | New certificate issued | cert_id, subject, issuer, not_before, not_after, purpose |
| Certificate.Revoked | Certificate revoked | cert_id, reason, revoked_by, revocation_time |
| Certificate.Expired | Certificate reached not_after | cert_id, subject, serial_number |
| Certificate.ValidationFailed | Chain validation failure | cert_id, reason, chain_length |
| Certificate.CRLPublished | CRL updated | crl_id, revoked_count, effective_date |

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R3 | Certificate schema defined in one place. |
| R10 | Linear chain validation, no branching validation paths. |
| R13 | Validation failure → deny connection (fail-closed). |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-CAM.md | CAM manages certificate lifecycle |
| 000-CSP.md | CSP verifies certificate signatures |
| HSM/000-HSM.md | CA private keys in HSM |
