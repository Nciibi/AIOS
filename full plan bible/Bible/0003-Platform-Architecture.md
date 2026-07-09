# AIOS Bible
## 0003 — Platform Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Root |
| Document ID | AIOS-BBL-0003 |
| Source Laws | All Laws — Platform architecture implements all constitutional requirements |
| Source Physics | Physics/000-Laws.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Platform Architecture defines the platform-wide view of AIOS — the infrastructure layer that supports all entities, services, and operations. The platform includes the lifecycle management system, state machine framework, event store, verification pipeline, communication fabric, and cryptography services. This document describes how these components fit together to form a coherent execution platform.

## Platform Overview

The AIOS platform consists of these major subsystems:

```
┌─────────────────────────────────────────────────────────────────┐
│                     AIOS Platform Architecture                      │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │                    Governance Layer                       │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │     │
│  │  │   CLS    │ │   DGP    │ │   CRP    │ │   ADG    │  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │     │
│  └──────────────────────────────────────────────────────────┘     │
│                              │                                      │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │                    Core Engine Layer                      │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │     │
│  │  │   Sou    │ │ Academy  │ │   OSYS   │ │   ROS    │  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │     │
│  └──────────────────────────────────────────────────────────┘     │
│                              │                                      │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │               Security Platform Layer                     │     │
│  │  ┌──────────────────┐  ┌──────────────────┐              │     │
│  │  │  Security Kernel │  │  Security Council│              │     │
│  │  │ (Pipeline Engine)│  │  (Governance)    │              │     │
│  │  └──────────────────┘  └──────────────────┘              │     │
│  └──────────────────────────────────────────────────────────┘     │
│                              │                                      │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │                Infrastructure Layer                       │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │     │
│  │  │   LMS    │ │EventStore│ │   ACF    │ │   CSP    │  │     │
│  │  │(Lifecycle)│ │(Evidence)│ │(Comm)   │ │(Crypto)  │  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │     │
│  └──────────────────────────────────────────────────────────┘     │
│                              │                                      │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │                   Runtime Layer                           │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                  │     │
│  │  │  Worker  │ │  Worker  │ │  Worker  │                  │     │
│  │  │ Runtime  │ │ Runtime  │ │ Runtime  │                  │     │
│  │  └──────────┘ └──────────┘ └──────────┘                  │     │
│  └──────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Responsibility | Key Components |
|-------|---------------|----------------|
| Governance | Constitutional compliance, decision routing, change management | CLS, DGP, CRP, ADG, CKR |
| Core Engine | Strategic decision-making, learning, resource orchestration | Sou, Academy, OSYS, ROS |
| Security | Identity, authentication, authorization, verification, enforcement | Security Kernel, Security Council |
| Infrastructure | Lifecycle management, event storage, communication, cryptography | LMS, Event Store, ACF, CSP |
| Runtime | Worker execution, sandboxing, resource consumption | Worker Runtimes, SDK |

## Infrastructure Components

### Lifecycle Management System (LMS)

The LMS provides the universal state machine framework for all entity lifecycles. Every entity type defines its states, valid transitions, and transition guards in the LMS.

**Key Properties**:
- Deterministic state machines — a given state and event always produces the same transition
- Transition guards — conditions that must be satisfied for a transition to be valid
- State persistence — entity states are stored in the Event Store as state snapshots
- Lifecycle hooks — entities can define actions on state entry, exit, and transition
- Lifecycle inheritance — entity types can inherit lifecycle definitions from parent types

**Entity Lifecycles Managed by LMS**:
| Entity Type | States | Transitions |
|-------------|--------|-------------|
| Resource | Draft → Validation → Approval → Instantiation → Active → Suspended → Archived | 21 |
| Mission | Created → Planned → Assigned → Running → Completed → Archived | 15 |
| Worker | Created → Initialized → Running → Completed → Destroyed | 10 |
| Identity | Created → Verified → Active → Suspended → Restored → Retired → Archived | 15 |
| Organization | Proposed → Ratified → Active → Restructuring → Dissolved | 8 |
| Session | Created → Active → Suspended → Terminated | 6 |

### Event Store (EVS)

The Event Store is the immutable, append-only record of all system Events. All system state is derived from the Event stream.

**Key Properties**:
- Immutable — Events are never modified or deleted after recording
- Append-only — new Events are appended, existing Events never change
- Ordered — Events have a global sequence number within a partition
- Schema-versioned — every Event type has a schema version for evolution
- Partitioned — Events are partitioned by entity ID for parallel access
- Replicated — Event Store data is replicated across nodes for durability

**Event Types**:
| Category | Examples | Retention |
|----------|----------|-----------|
| Governance | ConstitutionAmended, ADGApproved, RFCRatified | Indefinite |
| Identity | IdentityCreated, IdentityVerified, IdentityRetired | Indefinite |
| Security | AuthenticationEvent, AuthorizationDecision, PipelineResult | Indefinite |
| Execution | ActionStarted, ActionCompleted, ActionFailed | 90 days hot, 7 years cold |
| Lifecycle | StateTransition, EntityCreated, EntityDestroyed | 90 days hot, 7 years cold |
| Communication | MessageSent, MessageReceived, SubscriptionChanged | 30 days hot, 1 year cold |
| Knowledge | KnowledgeCreated, KnowledgeValidated, KnowledgeRetired | Indefinite |
| Debug | Heartbeat, StatusCheck, PerformanceMetric | 7 days, no archival |

### AI Communication Fabric (ACF)

ACF is the universal communication backbone. All inter-entity communication flows through ACF topics.

**Key Properties**:
- Topic-based publish/subscribe — entities publish to topics, subscribe to topics
- Hierarchical topic names — `aios/<domain>/<entity_type>/<entity_id>/<action>`
- Guaranteed delivery — at-least-once delivery within a partition
- Message ordering — messages within a topic partition are ordered
- Message signing — every message is signed by the sender's identity key
- Message routing — ACF routes messages based on topic subscriptions and routing policies
- Access control — topic-level access control enforced by the Security Kernel

**ACF Topic Structure**:
```
aios/
├── governance/     — Constitutional operations
│   ├── cls/        — CLS operations
│   ├── dgp/        — Decision routing
│   ├── crp/        — RFC lifecycle
│   └── adg/        — Architectural decisions
├── identity/       — Identity operations
│   └── irs/        — IRS operations
├── security/       — Security operations
│   └── kernel/     — Security Kernel operations
├── execution/      — Execution operations
│   ├── mission/    — Mission lifecycle
│   ├── worker/     — Worker operations
│   └── runtime/    — Runtime operations
├── knowledge/      — Knowledge operations
│   ├── academy/    — Academy operations
│   └── kms/        — Knowledge management
├── federation/     — Federation operations
│   ├── ixp/        — Instance exchange
│   └── cxp/        — Custom exchange
└── system/         — System operations
    ├── monitor/    — Monitoring and health
    └── audit/      — Audit events
```

### Cryptography Services (CSP)

The Cryptography Service Provider (CSP) provides all cryptographic operations to platform entities.

**Services**:
- Hashing (SHA-256, SHA-3) — evidence hashing, content addressing
- Signing (Ed25519, ECDSA) — message signing, identity verification
- Encryption (AES-256-GCM, ChaCha20-Poly1305) — data encryption
- Key Exchange (ECDH, X25519) — session key establishment
- Random Number Generation — cryptographic randomness
- Key Management — key generation, storage, rotation
- Hardware Security Module (HSM) integration — hardware-backed key storage

**Key Security Properties**:
- All cryptographic operations use well-established algorithms
- Key material is never exposed to entities — CSP performs operations on behalf of entities
- Session keys are ephemeral and never persisted
- Evidence hashes are chained for tamper detection
- HSM integration for high-security key operations

## Platform Invariants

These invariants must hold at all times in the platform:

| ID | Invariant | Enforced By |
|----|-----------|-------------|
| PLT-001 | Every entity is in exactly one lifecycle state | LMS |
| PLT-002 | Every action produces at least one Event | EVS |
| PLT-003 | All communication flows through ACF | ACF |
| PLT-004 | Every message is signed by a verified identity | CSP + Security Kernel |
| PLT-005 | Event Store is always append-only | EVS |
| PLT-006 | Entity state is derivable from Event stream | EVS |
| PLT-007 | Lifecycle transitions are deterministic | LMS |
| PLT-008 | Cryptographic keys never leave CSP | CSP |
| PLT-009 | Platform components are independently verifiable | Security Kernel |
| PLT-010 | Platform failures are isolated (no cascading) | ACF + LMS |

## Platform Scalability

### Horizontal Scaling
- Event Store partitions by entity ID
- ACF partitions by topic
- LMS state machines are entity-scoped
- Security Kernel verifications are per-action

### Vertical Scaling
- Cryptographic operations can use hardware acceleration (HSM, AES-NI)
- Event Store uses SSDs for low-latency writes
- ACF uses in-memory routing tables

### Bottlenecks
- Security Kernel verification is sequential (must be — Law 8)
- Event Store writes are sequential within a partition
- HSM operations are limited by hardware throughput

## Platform Resilience

### Fault Tolerance
- Event Store is replicated (Raft consensus)
- ACF routing is replicated
- LMS state machines are stateless (state in Event Store)
- Security Kernel is stateless (policies in CKR)

### Recovery
- Entity state is recovered from Event Store (event sourcing)
- ACF routing tables are rebuilt on restart
- LMS resumes monitoring from last checkpoint
- Security Kernel resumes verification from last known state

## Platform Security

### Security Boundaries
- Platform components operate in a trusted zone
- Runtimes operate in a sandboxed zone
- External integrations operate in a perimeter zone
- ACF enforces communication between zones

### Platform Component Security
- All platform components authenticate through IRS
- Platform-to-platform communication uses mTLS
- Platform configuration changes require Security Council approval
- Platform audit logs are immutable

## Related Documents

| Document | Relationship |
|---------|-------------|
| 0004-Service-Architecture.md | Service architecture — services run on the platform |
| 0005-Domain-Architecture.md | Domain architecture — domain entities use platform infrastructure |
| 0006-Reference-Architecture.md | Reference architecture — patterns used in the platform |
| 05-Platform (all documents) | Platform specifications — detailed component specifications |
| 06-Services/ACF (all documents) | ACF specifications — communication fabric details |
| 06-Services/Cryptography (all documents) | Cryptography specifications — cryptographic service details |
| 04-Execution/Security (all documents) | Security specifications — Security Kernel, pipelines |
| Physics/005-Events.md | Event invariants — Event Store derives from Law 4 |
| Physics/009-Interaction.md | Interaction invariants — ACF derives from Law 3 |
| Physics/010-Execution.md | Execution invariants — platform execution derives from Law 8 |
