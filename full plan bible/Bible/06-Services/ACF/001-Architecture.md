# AIOS Bible — Services
## ACF 001 — Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-001 |
| Source Laws | Law 4 — Law of Evidence, Law 5 — Law of Identity |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

ACF Architecture defines the component structure, data flow, clustering model, and addressing format of the Anticipatory Communication Fabric. This document provides the blueprint for how ACF is built and how messages flow through the system.

## Component Diagram

```
┌────────────────────────────────────────────────────────────┐
│ Sender Entity                                              │
│  ┌──────────┐                                              │
│  │  Entity  │───► ACF Gateway                              │
│  └──────────┘                                              │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ ACF Gateway                                                │
│  1. Receive message                                        │
│  2. Authenticate sender (verify token)                     │
│  3. Authorize message (check ACL)                          │
│  4. Assign message_id, timestamps                          │
│  5. Forward to Message Broker                              │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Message Broker                                             │
│  1. Persist message (if durable)                           │
│  2. Produce Event "MessageQueued"                          │
│  3. Forward to Router                                      │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Router                                                     │
│  1. Lookup target endpoint via routing table               │
│  2. Apply load balancing                                   │
│  3. Forward to target's delivery queue                     │
│  4. Produce Event "MessageRouted"                          │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ ACF Gateway (Receiver Side)                                │
│  1. Receive message from delivery queue                    │
│  2. Validate message integrity                             │
│  3. Deliver to receiver entity                             │
│  4. Produce Event "MessageDelivered"                       │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Receiver Entity                                            │
│  ┌──────────┐                                              │
│  │  Entity  │◄─── Delivered Message                        │
│  └──────────┘                                              │
└────────────────────────────────────────────────────────────┘
```

## Data Flow

The canonical data flow for every message:

```
Sender → ACF Gateway → Authenticate → Authorize → 
Message Broker → Router → Load Balancer → 
Delivery Queue → ACF Gateway → Receiver
```

Each step produces an Event. The full chain is:
1. `ACF.MessageSent` — Sender dispatched
2. `ACF.MessageAuthenticated` — Token verified
3. `ACF.MessageAuthorized` — Route permitted
4. `ACF.MessageQueued` — Persisted in broker
5. `ACF.MessageRouted` — Target selected
6. `ACF.MessageDelivered` — Receiver got it
7. `ACF.MessageAcknowledged` — Receiver processed (if ack required)

## ACF Clustering

ACF runs as a distributed cluster. The cluster model:

| Component | Consensus Protocol | Purpose |
|-----------|-------------------|---------|
| **Metadata store** | Raft | Routing tables, subscription state, cluster membership |
| **Message topics** | Partitioned | Throughput — topics are partitioned across brokers |
| **Delivery queues** | Sharded | Per-entity delivery queues, sharded by entity_id |

### Cluster Topology

- **Broker nodes**: Handle message ingestion and delivery. Stateless for messages (state is in the metadata store and partitioned topics).
- **Metadata nodes**: Run Raft for cluster-wide metadata. 3 or 5 nodes for fault tolerance.
- **Gateway nodes**: Edge proxies that handle authentication, authorization, and protocol adaptation.

## Addressing Format

ACF addressing follows Foundations/007-Naming-Conventions.md:

```
aios:{entity_type}:{sub_type}:{instance_id}
```

Examples:
- `aios:engine:sec:lms:001` — LMS instance
- `aios:engine:sec:evs:001` — Event Store instance
- `aios:org:001:a3f2c9d2` — Organization
- `aios:session:worker:004:d1e2f3a4` — Worker Session
- `aios:engine:sec:council:001` — Security Council

### Address Resolution

1. Sender provides target address in message envelope
2. ACF Gateway looks up target in routing table
3. Routing table maps patterns to active endpoints
4. If no route matches, message is rejected with `ACF.AddressUnresolvable`

## ACF Architecture Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.ClusterNodeJoined` | A new ACF node joins the cluster | node_id, node_type, endpoint |
| `ACF.ClusterNodeLeft` | A node leaves the cluster | node_id, reason |
| `ACF.ClusterLeaderElected` | A new Raft leader is elected | term, leader_id |
| `ACF.TopicPartitionReassigned` | A topic partition is reassigned | topic, partition, old_leader, new_leader |

## Cross-Cutting Concerns

### Security

Every message is authenticated (token verified) and authorized (route permitted) at the ACF Gateway. Messages without valid tokens are rejected with `ACF.AuthenticationFailed`. Unauthorized routes produce `ACF.AuthorizationDenied`.

### Evidence

Every step in the data flow produces an Event. The full chain of Events for a message provides a complete audit trail from sender to receiver.

### Lifecycle

ACF follows the Platform service lifecycle. Cluster nodes follow: Joining → Active → Leaving → Removed. Topics follow: Created → Active → Partitioned → Archived.

### Communication

ACF itself is the communication layer. ACF nodes communicate with each other through internal channels (not through ACF itself — that would be recursive).

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | ACF does one thing: inter-entity communication |
| R2 — Dependency Order | ACF is a foundational service; nothing above depends on it |
| R3 — DRY | Routing table is single source for message delivery |
| R4 — Builder Pattern | Messages are built by MessageBuilders with validation |
| R5 — Liskov | All transport backends implement the same Transport interface |
| R6 — DI over Singletons | ACF components receive dependencies via injection |
| R7 — Tests Exist | Every data flow step and cluster state has tests |
| R8 — Tests Fast | Message delivery tests complete in <5ms |
| R9 — Deterministic | Same message + same route always produces same delivery |
| R10 — Simpler Over Complex | ACF is a message bus; no complex orchestration |
| R11 — Refactor Over Rewrite | Cluster topology evolves via rolling upgrades |
| R12 — Embrace Errors | Every delivery failure has a unique error code |
| R13 — Design for Failure | Clustered with automatic failover |
| R14 — Paved Path | ACF is the only path for inter-entity communication |
| R15 — Open/Closed | New transport protocols extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Overview.md | ACF overview and component map |
| 002-Messages.md | Message schema and envelope format |
| 003-Routing.md | Routing table and load balancing |
| Foundations/007-Naming-Conventions.md | ACF addressing format |
| Physics/009-Interaction.md | Interaction invariants |
