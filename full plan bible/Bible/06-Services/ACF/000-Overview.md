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

## ACF Responsibilities

| Responsibility | Description | Enforced By |
|----------------|-------------|-------------|
| Message transport | Deliver messages from sender to receiver | Message Broker |
| Authentication | Verify sender identity on every message | ACF Gateway |
| Authorization | Verify sender may communicate with target | ACF Gateway + Router |
| Evidence | Produce Event for every message lifecycle step | Instrumentation layer |
| Routing | Determine delivery path for every message | Router |
| Durability | Persist messages for reliable delivery | Message Broker |
| Ordering | Maintain per-partition message ordering | Stream Processor |
| Backpressure | Protect publishers from slow consumers | Stream Processor |
| Federation | Bridge messages across AIOS instances | Distributed Coordinator |

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

1. **ACF-INV-001 — No Direct Communication**: No entity communicates directly with another entity. All messages pass through ACF. Direct entity-to-entity communication is a constitutional violation.

2. **ACF-INV-002 — Every Message Is Authenticated**: Every message carries a valid authentication token. Messages without valid tokens are rejected at the ACF Gateway. Token verification occurs before any routing.

3. **ACF-INV-003 — Every Message Is Authorized**: Messages are routed only if the sender is authorized to communicate with the target. Authorization is checked after authentication but before routing.

4. **ACF-INV-004 — Every Message Produces an Event**: Every message passing through ACF produces at least one Event. The full chain of Events (send, authenticate, authorize, route, deliver, acknowledge) provides a complete audit trail.

5. **ACF-INV-005 — At-Least-Once Delivery**: Every message is delivered at least once. Undeliverable messages go to the dead letter queue. At-most-once and exactly-once semantics are available per-message configuration.

## Component Map

| # | Document | Description | Key Responsibilities |
|---|----------|-------------|---------------------|
| 000 | **Overview** (this file) | ACF architecture overview | Invariants, component map, relationships |
| 001 | **Architecture** | Component diagram, data flow, clustering | Authentication, authorization, addressing |
| 002 | **Messages** | Message schema, envelope, delivery semantics | Envelope format, size limits, delivery modes |
| 003 | **Routing** | Routing rules, service discovery, load balancing | Pattern matching, endpoint selection |
| 004 | **Subscriptions** | Pub/sub, Event streams | Topic hierarchy, wildcards, durable subscriptions |
| 005 | **Streaming** | Stream processing, backpressure, ordering | Partition ordering, consumer groups |
| 006 | **Reliability** | Durability, delivery guarantees, dead letter | Retry policy, DLQ management |
| 007 | **Distributed** | Multi-instance ACF, partition tolerance, federation | ACF bridges, cross-instance messaging |

## Relationship to Other Volumes

| Volume | Relationship |
|--------|-------------|
| Physics/009-Interaction.md | Interaction invariants — ACF implements the communication model |
| Physics/005-Events.md | Every ACF message produces an Event |
| 05-Platform/003-PSAP.md | PSAP provides service discovery for ACF routing |
| 05-Platform/004-EVS.md | ACF delivers Events to the Event Store |
| 05-Platform/000-LMS.md | ACF carries LMS lifecycle messages |
| Security Council | ACF enforces authentication and authorization |
| Foundations/007-Naming-Conventions.md | ACF addressing format |
