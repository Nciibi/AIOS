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

## Architecture Overview

```
┌───────────────────────────────────────────────────────────┐
│                    ACF Architecture                         │
│  ┌─────────┐  ┌────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ Message │─►│ Router │─►│ Subscription │─►│  Stream  │ │
│  │ Broker  │  │        │  │  Manager     │  │Processor │ │
│  └─────────┘  └────────┘  └──────────────┘  └──────────┘ │
│       │            │              │               │        │
│       ▼            ▼              ▼               ▼        │
│  ┌──────────────────────────────────────────────────┐      │
│  │           Reliability Layer                       │      │
│  └──────────────────────────────────────────────────┘      │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────────────────────────────────────┐      │
│  │        Distributed Coordinator                    │      │
│  └──────────────────────────────────────────────────┘      │
└───────────────────────────────────────────────────────────┘
```

## 5 Invariants

1. **ACF-INV-001 — No Direct Communication**: No entity communicates directly with another entity. All messages pass through ACF.

2. **ACF-INV-002 — Every Message Is Authenticated**: Every message carries a valid authentication token. Messages without valid tokens are rejected.

3. **ACF-INV-003 — Every Message Is Authorized**: Messages are routed only if the sender is authorized to communicate with the target. Unauthorized messages are denied.

4. **ACF-INV-004 — Every Message Produces an Event**: Every message passing through ACF produces at least one Event for the evidence chain.

5. **ACF-INV-005 — At-Least-Once Delivery**: Every message is delivered at least once. Undeliverable messages go to the dead letter queue.

## Component Map

| # | Document | Description |
|---|----------|-------------|
| 000 | **Overview** (this file) | ACF architecture overview, invariants, component map |
| 001 | **Architecture** | Component diagram, data flow, clustering, addressing |
| 002 | **Messages** | Message schema, envelope, delivery semantics |
| 003 | **Routing** | Routing rules, service discovery, load balancing |
| 004 | **Subscriptions** | Pub/sub subscriptions, Event streams |
| 005 | **Streaming** | Stream processing, backpressure, ordering |
| 006 | **Reliability** | Message durability, delivery guarantees, dead letter |
| 007 | **Distributed** | Multi-instance ACF, partition tolerance, federation |

## Relationship to Other Volumes

| Volume | Relationship |
|--------|-------------|
| Physics/009-Interaction.md | Interaction invariants — ACF implements the communication model |
| Physics/005-Events.md | Every ACF message produces an Event |
| 05-Platform/003-PSAP.md | PSAP provides service discovery for ACF routing |
| 05-Platform/004-EVS.md | ACF delivers Events to the Event Store |
| 05-Platform/000-LMS.md | ACF carries LMS lifecycle messages |
| Security Council | ACF enforces authentication and authorization |
