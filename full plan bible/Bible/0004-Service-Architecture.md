# AIOS Bible
## 0004 — Service Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Root |
| Document ID | AIOS-BBL-0004 |
| Source Laws | All Laws — Service architecture implements all constitutional requirements |
| Source Physics | Physics/000-Laws.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Service Architecture describes how AIOS services interact, how they are deployed, and how they communicate. Services are the operational units that implement platform capabilities — communication, cryptography, federation, monitoring, and domain-specific operations. This document defines the service interaction patterns, deployment topology, service lifecycle, and inter-service dependencies.

## Service Taxonomy

AIOS services are categorized by function and criticality:

### By Function

| Category | Services | Description |
|----------|----------|-------------|
| Communication | ACF (Routing, Messages, Subscriptions, Streaming, Reliability, Distributed) | Inter-entity communication fabric |
| Cryptography | CSP, CAM, KMS, HSM, SMS, Signatures, Encryption, Hashing, Random | Cryptographic operations |
| Federation | AIP, RXP, MXP, KXP, GXP, OXP, SXP, EXP, TXP, PXP, CXP, IXP | Cross-instance and cross-protocol exchange |
| Domain | Domain-specific services (Phase 3+) | Business domain operations |

### By Criticality

| Criticality | Services | Failure Impact |
|-------------|----------|----------------|
| Tier 0 — Critical | ACF Routing, CSP, IRS (in Core) | System-wide failure |
| Tier 1 — High | ACF Messages, ACF Subscriptions, KMS, IXP | Service degradation |
| Tier 2 — Medium | ACF Streaming, Federation protocols (RXP, MXP, etc.) | Feature unavailability |
| Tier 3 — Low | Monitoring, logging, analytics | No user-facing impact |

## Service Interaction Patterns

### Pattern 1: Request-Response

Used for synchronous operations where an entity requests a service and waits for a response.

```
Entity ──Request──► Service
Entity ◄──Response── Service
```

**Examples**:
- Identity verification (Entity → IRS → Entity)
- Authorization check (Entity → Security Kernel → Entity)
- Knowledge query (Entity → KMS → Entity)

**ACF Implementation**:
- Request published to `aios/<domain>/<service>/<instance>/request`
- Response published to `aios/<domain>/<entity>/<entity_id>/response`
- Correlation ID links request and response

### Pattern 2: Publish-Subscribe

Used for event notification where one entity publishes events and multiple entities consume them.

```
Publisher ──Event──► ACF Topic
                        │
                    ┌───┴───┐
                    │       │
                    ▼       ▼
                Subscriber1 Subscriber2
```

**Examples**:
- Lifecycle state transitions (LMS publishes → OSYS subscribes)
- Evidence events (EVS publishes → Academy subscribes)
- Governance decisions (Security Council publishes → all entities subscribe)

**ACF Implementation**:
- Publisher writes to topic `aios/<domain>/<event_type>`
- Subscribers register interest via subscription
- ACF delivers events to all subscribers

### Pattern 3: Pipeline

Used for multi-stage processing where each stage processes and forwards.

```
Stage1 ──► Stage2 ──► Stage3 ──► Stage4
```

**Examples**:
- Security Kernel verification pipeline (Identity → Auth → Authz → Policy → Capability → Risk → ExecAuth)
- Academy learning pipeline (Collection → Filtering → Analysis → Validation → Storage)
- RFC lifecycle (Draft → Review → Approval → Implementation → Verification)

**ACF Implementation**:
- Each stage subscribes to its input topic
- Each stage publishes to the next stage's input topic
- Pipeline ID correlates stages

### Pattern 4: Streaming

Used for continuous data flow where data is processed in real-time.

```
Producer ──Stream──► Service ──Stream──► Consumer
```

**Examples**:
- Real-time monitoring data from Workers to monitoring service
- Live knowledge feed from Academy to subscribed entities
- Cross-instance data replication

**ACF Implementation**:
- ACF Streaming extension provides ordered, partitioned streams
- Stream consumers maintain cursor positions
- Streams are replayable from any cursor

### Pattern 5: Saga

Used for distributed transactions that span multiple services.

```
Step1 ──► Step2 ──► Step3 ──► Complete
  │         │         │
  ▼         ▼         ▼
Comp1     Comp2     Comp3
```

**Examples**:
- Worker creation (Identity creation → Capability assignment → Resource allocation → Runtime deployment)
- Mission execution (Mission creation → Worker assignment → Resource provisioning → Execution → Completion)
- Organization lifecycle (Proposal → Ratification → Member assignment → Operation → Dissolution)

**ACF Implementation**:
- Each step publishes progress to saga coordination topic
- Compensation steps are defined for each forward step
- Saga coordinator monitors progress and triggers compensation on failure

## Service Dependencies

### Dependency Rules

1. Services depend only on services in the same or lower tiers
2. No circular dependencies between services
3. Tier 0 services have zero dependencies on Tier 1+ services
4. Service dependencies are declared in service manifests
5. Dependency failures must not cascade (circuit breakers)

### Dependency Graph

```
Tier 0 (Critical):
  ├── ACF Routing
  └── CSP

Tier 1 (High):
  ├── ACF Messages ────► ACF Routing, CSP
  ├── ACF Subscriptions ──► ACF Routing
  ├── KMS ────► CSP
  └── IXP ────► ACF Routing, CSP

Tier 2 (Medium):
  ├── ACF Streaming ────► ACF Messages
  ├── Federation Protocols ──► IXP, ACF Messages
  │   ├── RXP ────► IXP
  │   ├── MXP ────► IXP
  │   ├── KXP ────► IXP, KMS
  │   ├── GXP ────► IXP
  │   ├── OXP ────► IXP
  │   ├── SXP ────► IXP
  │   ├── EXP ────► IXP
  │   ├── TXP ────► IXP
  │   ├── PXP ────► IXP
  │   └── CXP ────► IXP
  └── CAM ────► CSP

Tier 3 (Low):
  ├── HSM ────► CSP
  ├── SMS ────► CSP, KMS
  ├── Signatures ────► CSP
  ├── Encryption ────► CSP
  ├── Hashing ────► CSP
  └── Random ────► CSP
```

## Deployment Topology

### Single-Instance Deployment (Phase 1)

```
┌─────────────────────────────────────┐
│          AIOS Instance               │
│  ┌──────┐ ┌──────┐ ┌──────┐       │
│  │ Core  │ │Platform│ │Services│   │
│  │Engine │ │Infra  │ │(ACF,   │   │
│  │(Sou,  │ │(LMS,  │ │ CSP,  │   │
│  │Academy│ │EVS)   │ │ KMS)  │   │
│  └──────┘ └──────┘ └──────┘       │
│  ┌──────────────────────────────┐  │
│  │    Worker Runtime Pool        │  │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ │  │
│  │  │Worker│ │Worker│ │Worker│ │  │
│  │  │  A   │ │  B   │ │  C   │ │  │
│  │  └──────┘ └──────┘ └──────┘ │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

### Multi-Instance Deployment (Phase 4+)

```
┌─────────────┐     ┌─────────────┐
│ AIOS Instance│     │ AIOS Instance│
│    Alpha    │◄───►│    Beta     │
│             │ IXP │             │
│ ┌─────────┐ │     │ ┌─────────┐ │
│ │ Services│ │     │ │ Services│ │
│ └─────────┘ │     │ └─────────┘ │
│ ┌─────────┐ │     │ ┌─────────┐ │
│ │ Workers │ │     │ │ Workers │ │
│ └─────────┘ │     │ └─────────┘ │
└─────────────┘     └─────────────┘
```

### High-Availability Deployment

```
                     ┌──────────────┐
                     │   Load       │
                     │   Balancer   │
                     └──────┬───────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ AIOS Instance   │ │ AIOS Instance   │ │ AIOS Instance   │
│    Primary      │ │   Secondary     │ │   Secondary     │
│  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
│  │ Event Store│ │ │  │ Event Store│ │ │  │ Event Store│ │
│  │ (Leader)  │  │ │  │ (Follower) │ │ │  │ (Follower) │ │
│  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Service Lifecycle

Each service follows a defined lifecycle:

```
Designed → Implemented → Deployed → Active → Deprecated → Retired
```

| Stage | Activities | Evidence Required |
|-------|-----------|-------------------|
| Designed | RFC drafted, ADG approved | ADG decision, RFC document |
| Implemented | Code written, tested | Test results, code review |
| Deployed | Service deployed to platform | Deployment record |
| Active | Service operational | Health checks, metrics |
| Deprecated | Service no longer recommended | Deprecation notice, migration guide |
| Retired | Service removed | Data migration record, shutdown evidence |

## Service Health and Monitoring

### Health Check Protocol
Every service exposes a health check endpoint through ACF:
- `aios/<domain>/<service>/<instance>/health` — returns service status
- Response: `{ status: "healthy" | "degraded" | "unhealthy", latency_ms, uptime_seconds, version }`

### Monitoring Metrics
Services produce standard monitoring metrics:
- Request rate (requests/second)
- Latency (p50, p95, p99)
- Error rate (errors/second)
- Resource utilization (CPU, memory, network, storage)
- Queue depth (for queued services)

### Alert Thresholds
| Metric | Warning | Critical |
|--------|---------|----------|
| Latency p99 | > 500ms | > 2000ms |
| Error rate | > 1% | > 5% |
| Queue depth | > 1000 | > 10000 |
| Resource utilization | > 80% | > 95% |

## Service Versioning

Services follow semantic versioning:
- **MAJOR**: Breaking API changes, protocol changes, data format changes
- **MINOR**: Backward-compatible new features, new endpoints
- **PATCH**: Bug fixes, security patches, performance improvements

### Version Compatibility
- Services within the same MAJOR version are interoperable
- Service consumers declare minimum and maximum compatible versions
- ACF routing can direct consumers to compatible service versions
- Multiple service versions may run simultaneously during migration

## Related Documents

| Document | Relationship |
|---------|-------------|
| 0003-Platform-Architecture.md | Platform architecture — services run on the platform infrastructure |
| 0005-Domain-Architecture.md | Domain architecture — domain entities use services |
| 0006-Reference-Architecture.md | Reference architecture — service interaction patterns |
| 06-Services (all documents) | Service specifications — detailed service documentation |
| 06-Services/ACF (all documents) | ACF specifications — communication fabric for service interactions |
| 06-Services/Federation (all documents) | Federation specifications — cross-instance service protocols |
| 06-Services/Cryptography (all documents) | Cryptography specifications — cryptographic services |
| 08-Interfaces/API | API specifications — service API documentation |
| 00-Foundations/002-Design-DNA.md | Design DNA — service design follows R1–R15 |
