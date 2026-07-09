# AIOS Bible — Services
## ACF 005 — Streaming

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-005 |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Stream processing, backpressure, and ordering guarantees for ACF messages. Streams extend the subscription model to provide ordered sequences of messages on a topic with consumer groups for load distribution. Streams enable Event-driven processing at scale.

## Stream Model

```
Stream {
  id: UUID,
  topic: string,
  partitions: Partition[],
  config: StreamConfig,
  created_at: timestamp
}

Partition {
  id: int,                       // 0-based partition index
  messages: OrderedMessage[],    // ordered sequence
  consumer_group: ConsumerGroup?,
  leader: NodeID,                // broker node responsible
  replicas: NodeID[]             // replica nodes
}

ConsumerGroup {
  id: string,
  consumers: Consumer[],
  strategy: PartitionAssignment,
  state: Active | Rebalancing
}

Consumer {
  id: string,
  entity_id: EntityID,
  assigned_partitions: int[],
  position: map<int, int>,       // partition → sequence number
  last_heartbeat: timestamp,
  status: Connected | Disconnected
}
```

## Ordering Guarantees

| Scope | Guarantee | Mechanism |
|-------|-----------|-----------|
| Within a partition | Strict ordering | Monotonic sequence numbers |
| Across partitions | No ordering | Timestamp correlation |
| Cross-stream | No ordering | Application-level correlation |

### Per-Partition Ordering

Messages within a partition receive monotonic sequence numbers at append time:

```
sequence = partition.current_sequence + 1
```

Consumers receive messages in sequence number order. If a consumer disconnects and reconnects, it resumes from `last_committed_sequence + 1`.

### Partition Key

Messages may specify a partition key. Messages with the same key go to the same partition, preserving order within that key:

```
partition_id = hash(partition_key) % partition_count
```

## Consumer Groups

Consumer groups distribute partitions across multiple consumers for parallel processing:

| Assignment Strategy | Description | Rebalance Cost |
|---------------------|-------------|----------------|
| **round-robin** | Partitions evenly distributed | Low |
| **hash** | Partition assigned by message key hash | Low |
| **sticky** | Consumer keeps partition on reconnect | Medium |
| **manual** | Explicit partition assignment | None (manual) |

### Consumer Group Rebalancing

When a consumer joins or leaves:

```
1. Group coordinator detects change (join/leave heartbeat)
2. Coordinator initiates rebalance
3. State: Active → Rebalancing
4. All consumers pause processing
5. Revoke current partition assignments
6. Consumers commit their current position
7. Reassign partitions per strategy
8. Consumers receive new assignments
9. State: Rebalancing → Active
10. Consumers resume from committed position
```

## Backpressure

ACF applies backpressure when consumers cannot keep up:

| Level | Condition | Action |
|-------|-----------|--------|
| **Normal** | Lag < 10% of buffer | No action |
| **Warning** | Lag > 50% of buffer | Produce BackpressureWarning Event |
| **Critical** | Lag > 80% of buffer | Apply backpressure to producer |
| **Overflow** | Buffer full | Drop oldest (volatile) or pause (durable) |

### Backpressure Mechanisms

- **Producer throttling**: Reduce producer publish rate via TCP backpressure
- **Buffer expansion**: Grow buffer up to configurable max (default 10000 messages)
- **Message drop**: Drop oldest messages for volatile streams
- **Consumer scaling**: Recommend adding consumers (automatic if configured)

### Buffer Configuration

```
StreamBufferConfig {
  max_buffered_messages: int,      // default 10000
  max_buffered_bytes: int,         // default 100 MB
  backpressure_threshold: float,   // 0.0–1.0, default 0.8
  drop_oldest_when_full: bool,     // default false (for volatile: true)
  consumer_notify_interval: duration // how often to check consumer lag
}
```

## Stream Operations

```
createStream(topic, partitions, config) → stream_id
deleteStream(stream_id) → void
publishToStream(topic, message, partition_key?) → sequence_number
publishToPartition(stream_id, partition_id, message) → sequence_number
consumeStream(stream_id, consumer_group, consumer_id) → subscription_id
getStreamPosition(consumer_group, consumer_id, partition_id?) → position
seekStream(consumer_group, consumer_id, position) → void
commitPosition(consumer_group, consumer_id, partition_id, sequence) → void
getStreamInfo(stream_id) → StreamInfo
listStreams(filter?) → StreamInfo[]
```

### Consumer Position Management

| Position Type | Description | Use Case |
|---------------|-------------|----------|
| **earliest** | Start from beginning | Full replay |
| **latest** | Start from most recent | New consumer |
| **sequence** | Start from specific sequence | Resumption |
| **timestamp** | Start from specific time | Time-based replay |

### Commit Protocol

Consumers commit their position to mark messages as processed:

```
1. Consumer processes message at sequence N in partition P
2. Consumer sends commit(P, N) to coordinator
3. Coordinator records position
4. If consumer crashes, new consumer resumes from last committed
5. Uncommitted messages are redelivered
```

## ACF Streaming Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.StreamCreated` | Stream created | stream_id, topic, partition_count, config |
| `ACF.StreamDeleted` | Stream deleted | stream_id, message_count, reason |
| `ACF.PartitionReassigned` | Partition reassigned | partition_id, consumer_group, old_consumer, new_consumer, reason |
| `ACF.ConsumerAdded` | Consumer joins group | consumer_id, consumer_group, stream_id |
| `ACF.ConsumerRemoved` | Consumer leaves | consumer_id, consumer_group, reason |
| `ACF.ConsumerRebalanced` | Group rebalanced | consumer_group, previous_assignments, new_assignments |
| `ACF.StreamEnd` | Stream reaches end | stream_id, last_sequence |
| `ACF.BackpressureApplied` | Backpressure triggered | stream_id, level, consumer_group, buffer_usage_pct |
| `ACF.BackpressureOverflow` | Buffer overflow | stream_id, messages_dropped, drop_strategy |
| `ACF.PositionCommitted` | Consumer commits position | consumer_group, consumer_id, partition_id, sequence |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| ACF-STR-001 | StreamNotFound | No stream with the given ID |
| ACF-STR-002 | PartitionNotFound | Partition does not exist |
| ACF-STR-003 | ConsumerNotFound | Consumer not in group |
| ACF-STR-004 | ConsumerGroupNotFound | Group does not exist |
| ACF-STR-005 | InvalidPosition | Seek position out of range |
| ACF-STR-006 | RebalanceInProgress | Cannot consume during rebalance |
| ACF-STR-007 | BufferFull | Stream buffer is full |

## Cross-Cutting Concerns

### Security

Stream access requires authorization. Publishers must have publish permission. Consumers must have consume permission. Stream metadata access is restricted.

### Evidence

Every stream lifecycle operation produces an Event. Consumer position commits produce Events for audit. Backpressure Events are recorded.

### Lifecycle

Streams follow: Created → Active → Rebalancing → Archived → Deleted. Consumer groups follow: Created → Active → Rebalancing → Depleted.

### Capability Bounds

Streaming only manages ordered message delivery with consumer groups. It does not process message content (EPG does), does not store messages long-term (EVS does), and does not filter (Subscriptions do).

### Communication

Streaming is entirely within ACF. Publishers and consumers communicate through ACF. Stream metadata operations use ACF messages.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Streaming does one thing: ordered message delivery with groups |
| R2 — Dependency Order | Streaming depends on ACF Core; no upward deps |
| R3 — DRY | Stream configurations are stored once |
| R4 — Builder Pattern | Streams are built by StreamBuilders |
| R5 — Liskov | All partition assignment strategies implement same interface |
| R6 — DI over Singletons | Stream Manager receives ACF as injected dependency |
| R7 — Tests Exist | Every ordering guarantee and rebalance scenario has tests |
| R8 — Tests Fast | Stream operations complete in <5ms |
| R9 — Deterministic | Same messages in same order always produce same sequence |
| R10 — Simpler Over Complex | Per-partition ordering; no global ordering |
| R11 — Refactor Over Rewrite | Stream schemas evolve via versioned updates |
| R12 — Embrace Errors | Every stream failure has a unique error code |
| R13 — Design for Failure | Backpressure protects from slow consumers |
| R14 — Paved Path | ACF Streaming is the only path for ordered message streams |
| R15 — Open/Closed | New partition strategies extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 004-Subscriptions.md | Streams extend subscriptions with ordering |
| 002-Messages.md | Stream messages use the message schema |
| 006-Reliability.md | Delivery guarantees for streams |
| 05-Platform/006-EPG.md | EPG consumes Event streams |
| Physics/005-Events.md | Event ordering invariants |
