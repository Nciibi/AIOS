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
│  1. Receive message from entity                            │
│  2. Authenticate sender (verify auth_token)                │
│  3. Authorize message (check ACL for sender→target)        │
│  4. Assign message_id (UUIDv7), timestamp (HLC)            │
│  5. Extract envelope, validate required fields             │
│  6. Forward to Message Broker                              │
│  7. Produce ACF.MessageSent Event                          │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Message Broker                                             │
│  1. Receive validated message from Gateway                 │
│  2. If durable: write to WAL (write-ahead log)             │
│  3. Assign queue position                                  │
│  4. Forward to Router                                      │
│  5. Produce ACF.MessageQueued Event                        │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Router                                                     │
│  1. Look up target endpoint in routing table               │
│  2. Apply pattern matching (most specific wins)            │
│  3. Filter by health status (PSAP integration)             │
│  4. Apply load balancing strategy                          │
│  5. Forward to target's delivery queue                     │
│  6. Produce ACF.MessageRouted Event                        │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Delivery Queue (Per-Receiver)                              │
│  1. Queue message for receiver                             │
│  2. If receiver is offline: buffer (configurable)          │
│  3. Deliver to receiver's ACF Gateway                      │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ ACF Gateway (Receiver Side)                                │
│  1. Receive message from delivery queue                    │
│  2. Validate message integrity (check hash)                │
│  3. Deliver to receiver entity                             │
│  4. Wait for acknowledgment (configurable timeout)         │
│  5. Produce ACF.MessageDelivered Event                     │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ Receiver Entity                                            │
│  ┌──────────┐                                              │
│  │  Entity  │◄─── Message delivered                        │
│  │          │───► Acknowledgment sent                      │
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

Each step produces an Event. The full Event chain for a message:

| Step | Event | Produced By |
|------|-------|-------------|
| 1. Sender dispatches | `ACF.MessageSent` | Sender's ACF Gateway |
| 2. Token verified | `ACF.MessageAuthenticated` | ACF Gateway |
| 3. Route permitted | `ACF.MessageAuthorized` | ACF Gateway |
| 4. Message persisted | `ACF.MessageQueued` | Message Broker |
| 5. Target selected | `ACF.MessageRouted` | Router |
| 6. Delivered to receiver | `ACF.MessageDelivered` | Receiver's ACF Gateway |
| 7. Receiver acknowledges | `ACF.MessageAcknowledged` | Receiver's ACF Gateway |

## ACF Clustering

ACF runs as a distributed cluster with three node roles:

| Node Role | Consensus | Data | Scaling |
|-----------|-----------|------|---------|
| **Metadata nodes** | Raft | Routing tables, subscriptions, cluster membership | 3 or 5 nodes |
| **Broker nodes** | Partitioned | Message topics, delivery queues | Horizontal (add partitions) |
| **Gateway nodes** | Stateless | None | Horizontal (add instances) |

### Metadata Store (Raft)

Manages cluster-wide state: routing tables, subscription state, topic partitions, cluster membership. Raft ensures consistency across the cluster. Reads are served by any metadata node. Writes go through the Raft leader.

### Topic Partitioning

Topics are partitioned for throughput:

| Aspect | Configuration |
|--------|--------------|
| Default partitions per topic | 3 |
| Max partitions per topic | 100 |
| Partition assignment | Consistent hashing on partition key |
| Replication factor | 2 (leader + 1 follower) |

### Delivery Queue Sharding

Per-entity delivery queues are sharded by entity_id:

```
queue_{entity_id_hash % shard_count}
```

Default shard count: 10. Configurable per instance.

## Addressing Format

ACF addressing follows Foundations/007-Naming-Conventions.md:

```
aios:{entity_type}:{sub_type}:{instance_id}
```

| Segment | Description | Example |
|---------|-------------|---------|
| prefix | Always `aios:` | `aios:` |
| entity_type | Entity type | `engine`, `session`, `org` |
| sub_type | Optional qualifier | `sec`, `worker`, `user_int` |
| instance_id | Instance identifier | `lms:001`, `001:a3f2c9d2` |

Examples:
- `aios:engine:sec:lms:001` — LMS instance 001
- `aios:engine:sec:evs:001` — Event Store instance 001
- `aios:org:001:a3f2c9d2` — Organization
- `aios:session:worker:004:d1e2f3a4` — Worker Session
- `aios:engine:sec:council:001` — Security Council
- `aios:user:008:a1b2c3d4` — User

### Address Resolution

1. Sender provides target address in message envelope
2. ACF Gateway strips the `aios:` prefix
3. Router matches address against routing table patterns
4. Pattern matching: direct match → type match → wildcard match
5. If no match, return `ACF.AddressUnresolvable`
6. If matched, return endpoint(s) for delivery

## Performance Targets

| Metric | Target |
|--------|--------|
| Message throughput | >100000 messages/s per broker node |
| P50 latency | <10ms (intra-instance) |
| P99 latency | <100ms (intra-instance) |
| Max message size | 10MB (default), 100MB (max) |
| Max concurrent connections | 10000 per gateway node |
| Cluster size | Up to 100 nodes |

## ACF Architecture Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.ClusterNodeJoined` | New node joins cluster | node_id, node_type, endpoint, cluster_size |
| `ACF.ClusterNodeLeft` | Node leaves cluster | node_id, node_type, reason, uptime_seconds |
| `ACF.ClusterLeaderElected` | New Raft leader | term, leader_id, previous_leader |
| `ACF.TopicPartitionCreated` | Topic partition created | topic, partition, node_assignment |
| `ACF.TopicPartitionReassigned` | Partition reassigned | topic, partition, old_leader, new_leader, reason |

## Cross-Cutting Concerns

### Security

Every message is authenticated (token verified) and authorized (route permitted) at the ACF Gateway. Messages without valid tokens are rejected. Unauthorized routes are denied. All gateway operations log security Events.

### Evidence

Every step in the data flow produces an Event. The full chain of Events for a message provides a complete audit trail from sender to receiver.

### Lifecycle

ACF follows the Platform service lifecycle. Cluster nodes follow: Joining → Syncing → Active → Leaving → Removed. Topics follow: Created → Active → Partitioned → Archived.

### Communication

ACF itself is the communication layer. ACF nodes communicate with each other through internal channels (not through ACF itself — that would be recursive). Internal communication uses a lightweight protocol over TCP with mTLS.

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
