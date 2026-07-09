# AIOS Bible — Identity Service (IDS)
## 000 — Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Identity |
| Document ID | AIOS-BBL-IDS-000 |
| Source Laws | Law 5 — Law of Identity |
| Source Physics | Physics/001-Identity.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document introduces the Identity Service (IDS) — the constitutional institution responsible for identity creation, verification, lifecycle management, resolution, and federation within AIOS. IDS is the sole authority for identity. Every entity that participates in constitutional operations receives its identity from IDS.

IDS answers one question: *Who or what is this constitutional entity?*

IDS does not authenticate, does not authorize, does not evaluate trust. It establishes identity — the immutable root upon which all other security functions are built.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────┐
│                    IDS Instance                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ Identity  │  │ Registry  │  │ Clock     │           │
│  │ Factory   │  │ Store     │  │ Authority │           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │              │              │                │
│       ▼              ▼              ▼                │
│  ┌──────────────────────────────────────────────────┐│
│  │                  ACF Gateway                     ││
│  └──────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

| Component | Responsibility |
|-----------|---------------|
| **Identity Factory** | Creates new identities, validates provenance, generates identity IDs, computes signatures |
| **Registry Store** | Persistent identity storage, query, index, cache. Append-only event log for identity lifecycle |
| **Clock Authority** | Monotonic clock synchronization across all IDS instances. Assigns sequence numbers to identity Events |
| **ACF Gateway** | Handles incoming identity requests over ACF, authenticates requesters, routes responses |

### Cluster Architecture

IDS runs as a clustered service:
- **Active-Passive replication**: One primary, one or more standbys. Failover within 5 seconds.
- **Read replicas**: Query-only, eventual consistency (<100ms lag).
- **Partition tolerance**: On network partition, each partition elects a primary. Reconciliation: highest Event sequence number wins. Conflicting identities flagged for manual resolution.
- **Clock synchronization**: Hybrid logical clock (HLC), drift bounded to 50ms cross-instance.

### Data Store

The Registry Store uses an append-only event log:

```
IdentityCreated(id, type, provenance, timestamp, signature)
IdentityVerified(id, timestamp, signature)
IdentitySuspended(id, reason, authorizing_entity, timestamp)
IdentityRestored(id, reason, authorizing_entity, timestamp)
IdentityRetired(id, reason, authorizing_entity, timestamp, evidence_hash)
IdentityMetadataUpdated(id, metadata_diff, timestamp)
```

Current identity state is a projection of the event log, enabling full audit history and point-in-time reconstruction.

## Identity ID Format

```
aios:${entity_type}:${random_suffix}
```

Examples: `aios:org:001:a3f7c9d1`, `aios:session:worker:004:b8e2f1a3`, `aios:engine:sec:irs:001`

The suffix is a cryptographically random 32-bit hex string. Collision probability is negligible (1/2³² per pair, reduced by entity type namespace separation).

## Identity Integrity

### Cryptographic Signatures

```
hash = SHA256(identity_id || entity_type || entity_id || status || created_at || salt)
signature = ECDSA(IDS_private_key, hash)
```

### Event Chain Integrity

Identities are chained: `Event N: data = { ..., prev_hash = SHA256(Event N-1) }`. Tampering with any event invalidates all subsequent events.

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md, Law 5 | Identity — source law |
| Physics/001-Identity.md | 10 Identity invariants — IDS implements them |
| Physics/005-Events.md | Event schema — IDS produces identity Events |
| Physics/008-Security.md | Security framework — identity is the first stage |
| IDS/001-Registry.md | Registry Store specification |
| IDS/002-Resolution.md | Identity resolution API |
| IDS/003-Lifecycle.md | Identity lifecycle management |
| IDS/004-Federation.md | Cross-instance identity federation |
| IDS/005-Provenance.md | Identity provenance and audit trails |