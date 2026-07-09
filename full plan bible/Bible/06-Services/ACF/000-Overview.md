# AIOS Bible — Services
## ACF 000 — Anticipatory Communication Fabric Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-000 |
| Source Laws | Law 4 — Law of Evidence, Law 5 — Law of Identity |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

ACF is AIOS's internal message bus. Every communication flows through ACF. No entity communicates directly with another entity — all inter-entity messages pass through ACF. ACF enforces authentication (every message has a valid token), authorization (messages are routed only if permitted), and evidence (every message produces an Event). ACF is not optional — it is the sole communication channel for ALL inter-entity messages.

## Constitutional Grounding

ACF derives from Physics/009-Interaction.md, which establishes the invariant that all inter-entity communication must go through a constitutional communication layer. ACF implements this invariant. The Constitution mandates that no entity may directly address another entity — all communication must be mediated by ACF to ensure authentication, authorization, and evidence capture.

## ACF Responsibilities

| Responsibility | Description | Enforced By | Source Invariant |
|----------------|-------------|-------------|-----------------|
| Message transport | Deliver messages from sender to receiver | Message Broker | PHI-009-001 |
| Authentication | Verify sender identity on every message | ACF Gateway | PHI-009-002 |
| Authorization | Verify sender may communicate with target | ACF Gateway + Router | PHI-009-003 |
| Evidence | Produce Event for every message lifecycle step | Instrumentation layer | PHI-005-001 |
| Routing | Determine delivery path for every message | Router | PHI-009-004 |
| Durability | Persist messages for reliable delivery | Message Broker | PHI-009-005 |
| Ordering | Maintain per-partition message ordering | Stream Processor | CPR-006 |
| Backpressure | Protect publishers from slow consumers | Stream Processor | CPR-007 |
| Federation | Bridge messages across AIOS instances | Distributed Coordinator | CPR-008 |

## Architecture Overview

```
┌───────────────────────────────────────────────────────────┐
│                    ACF Architecture                         │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐         │
│  │ Message  │───►│  Router  │───►│ Subscription │         │
│  │ Broker   │    │          │    │  Manager     │         │
│  └──────────┘    └──────────┘    └──────────────┘         │
│       │               │               │                    │
│       ▼               ▼               ▼                    │
│  ┌──────────────────────────────────────────────────┐      │
│  │               Stream Processor                    │      │
│  │  (order, backpressure, consumer groups)          │      │
│  └──────────────────────────────────────────────────┘      │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────────────────────────────────────┐      │
│  │            Reliability Layer                      │      │
│  │  (retry, dead letter, delivery guarantees)       │      │
│  └──────────────────────────────────────────────────┘      │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────────────────────────────────────┐      │
│  │        Distributed Coordinator                   │      │
│  │  (federation, partition tolerance, Raft)        │      │
│  └──────────────────────────────────────────────────┘      │
└───────────────────────────────────────────────────────────┘
```

## 5 Invariants

1. **ACF-INV-001 — No Direct Communication**: No entity communicates directly with another entity. All messages pass through ACF. Direct entity-to-entity communication is a constitutional violation. This invariant is enforced at the ACF Gateway, which rejects messages that appear to be direct.

2. **ACF-INV-002 — Every Message Is Authenticated**: Every message carries a valid authentication token. Messages without valid tokens are rejected at the ACF Gateway. Token verification occurs before any routing. Authentication tokens include session tokens, API keys, and certificate-based tokens. The auth_type field specifies the token type.

3. **ACF-INV-003 — Every Message Is Authorized**: Messages are routed only if the sender is authorized to communicate with the target. Authorization is checked after authentication but before routing. The authorization check verifies: (a) the sender has permission to send to the target's entity type, (b) the target has permission to receive from the sender's entity type, and (c) no policy restriction blocks this communication. Unauthorized messages produce an `ACF.AuthorizationDenied` Event.

4. **ACF-INV-004 — Every Message Produces an Event**: Every message passing through ACF produces at least one Event. The full chain of Events (send, authenticate, authorize, route, deliver, acknowledge) provides a complete audit trail for every communication. Events are stored in the Event Store (05-Platform/004-EVS.md) and are queryable via the Audit Service (05-Platform/005-AUS.md).

5. **ACF-INV-005 — At-Least-Once Delivery**: Every message is delivered at least once. If the receiver does not acknowledge delivery within the configured timeout, the message is retried with exponential backoff. After exhausting retries, the message is sent to the dead letter queue for human review.

## Design Decisions

| Decision | Rationale | Alternatives Considered |
|----------|-----------|------------------------|
| All messages go through ACF | Single point for auth, audit, and enforcement | Direct entity messaging (rejected: violates constitutional invariants) |
| Hierarchical topics with wildcards | Familiar, simple, expressive | Flat topics (rejected: insufficient expressiveness) |
| Raft for metadata consensus | Proven, simple, well-understood | Paxos (rejected: complexity), Gossip (rejected: consistency requirements) |
| At-least-once as default | Balances reliability and performance | Exactly-once (rejected: performance cost for general use) |
| Dead letter queue | Prevents message loss, enables review | Silent discard (rejected: violates evidence invariant) |

## Component Map

| # | Document | Description | Key Responsibilities |
|---|----------|-------------|---------------------|
| 000 | **Overview** (this file) | ACF architecture overview | Invariants, component map, relationships |
| 001 | **Architecture** | Component diagram, data flow, clustering | Authentication, authorization, addressing, gateway flow |
| 002 | **Messages** | Message schema, envelope, delivery semantics | Envelope format, size limits, delivery modes, priority |
| 003 | **Routing** | Routing rules, service discovery, load balancing | Pattern matching, endpoint selection, PSAP integration |
| 004 | **Subscriptions** | Pub/sub, Event streams | Topic hierarchy, wildcards, durable subscriptions, filters |
| 005 | **Streaming** | Stream processing, backpressure, ordering | Partition ordering, consumer groups, rebalancing |
| 006 | **Reliability** | Durability, delivery guarantees, dead letter | Retry policy, DLQ management, targets |
| 007 | **Distributed** | Multi-instance ACF, partition tolerance, federation | ACF bridges, cross-instance messaging, conflict resolution |

## Relationship to Other Volumes

| Volume | Relationship | Key Interaction |
|--------|-------------|-----------------|
| Physics/009-Interaction.md | Interaction invariants — ACF implements the communication model | ACF enforces PHI-009 invariants at the messaging layer |
| Physics/005-Events.md | Every ACF message produces an Event | ACF Gateway produces Events for each lifecycle step |
| 05-Platform/003-PSAP.md | PSAP provides service discovery for ACF routing | Router queries PSAP for healthy endpoints |
| 05-Platform/004-EVS.md | ACF delivers Events to the Event Store | ACF streams Events to EVS for persistence |
| 05-Platform/000-LMS.md | ACF carries LMS lifecycle messages | LMS transition requests and responses flow through ACF |
| Security Council | ACF enforces authentication and authorization | ACF Gateway verifies tokens; Router enforces ACLs |
| Foundations/007-Naming-Conventions.md | ACF addressing format | All ACF addresses follow the canonical naming format |
| 05-Platform/008-BG.md | BG may bypass ACF controls in emergency | BG sessions can override ACF authorization |

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Message throughput | >100K msg/s per node | Continuous monitoring |
| P50 latency (intra-instance) | <10ms | Rolling 1 hour |
| P99 latency (intra-instance) | <100ms | Rolling 1 hour |
| Delivery rate | 99.99% | Rolling 30 days |
| Durability (persistent) | 99.9999% | Per-message |
| DLQ rate | <0.1% | Rolling 7 days |
| Cluster availability | 99.99% | Annual |
