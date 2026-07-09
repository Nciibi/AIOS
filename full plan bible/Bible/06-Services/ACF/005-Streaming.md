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
  topic: string,
  partitions: Partition[],
  config: StreamConfig
}

Partition {
  id: int,
  messages: OrderedMessage[],
  consumer_group: ConsumerGroup?
}

ConsumerGroup {
  id: string,
  consumers: Consumer[],
  strategy: PartitionAssignment
}
```

### Ordered Message Sequence

A stream is an ordered sequence of messages on a topic. Messages within a partition are strictly ordered. Partitions allow parallel processing while maintaining per-partition ordering.

## Ordering Guarantees

| Scope | Ordering Guarantee |
|-------|-------------------|
| **Within a partition** | Strict — messages delivered in append order |
| **Across partitions** | Best-effort — correlate by timestamp |
| **Cross-stream** | No ordering guarantee |

### Per-Partition Ordering

Messages within a partition are assigned monotonic sequence numbers. Consumers receive messages in sequence number order. If a consumer disconnects and reconnects, it resumes from the last acknowledged sequence number.

### Cross-Partition Ordering

Messages across partitions can be correlated using their HLC timestamps. ACF provides timestamp-based correlation but does not enforce cross-partition ordering. Applications that need global ordering use a single partition.

## Consumer Groups

Consumer groups enable load distribution across multiple consumers:

| Partition Assignment | Description | Use Case |
|---------------------|-------------|----------|
| **round-robin** | Partitions evenly distributed | Homogeneous consumers |
| **hash** | Partition assigned by message key | Key-based ordering |
| **sticky** | Consumer keeps partition on reconnect | Stateful consumers |
| **manual** | Explicit partition assignment | Custom distribution |

### Consumer Group Rebalancing

When a consumer joins or leaves a group, partitions are rebalanced:

```
1. Consumer joins/leaves detected
2. Group coordinator initiates rebalance
3. All consumers pause processing
4. Partitions reassigned according to strategy
5. Consumers resume with new assignments
6. Produces ConsumerRebalanced Event
```

## Backpressure

ACF applies backpressure when consumers cannot keep up with the publish rate:

| Level | Condition | Action |
|-------|-----------|--------|
| **Normal** | Consumer lag < 10% of buffer | No action |
| **Warning** | Consumer lag > 50% of buffer | Produce BackpressureWarning Event |
| **Critical** | Consumer lag > 80% of buffer | Slow publisher, apply backpressure to producer |
| **Overflow** | Buffer full | Drop oldest messages (configurable), produce BackpressureOverflow |

### Backpressure Mechanisms

- **Producer throttling**: Publisher is slowed to match consumer rate
- **Buffer expansion**: Buffer grows up to configurable max
- **Message drop**: Oldest messages are dropped (only for volatile streams)
- **Consumer scaling**: New consumer instances are suggested

## Stream Operations

```
createStream(topic, partitions, config) → stream_id
publishToStream(stream_id, partition_key?, message) → sequence_number
consumeStream(stream_id, consumer_group, consumer_id) → subscription_id
getStreamPosition(consumer_group, consumer_id) → position
seekStream(consumer_group, consumer_id, position) → void
commitPosition(consumer_group, consumer_id, position) → void
getStreamInfo(stream_id) → StreamInfo
deleteStream(stream_id) → void
```

### Consumer Position Management

Consumers track their position in the stream. Positions are committed to allow resumption after restart:

| Position Type | Description |
|---------------|-------------|
| **earliest** | Start from beginning of stream |
| **latest** | Start from most recent message |
| **sequence** | Start from specific sequence number |
| **timestamp** | Start from specific timestamp |

## ACF Streaming Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.StreamCreated` | A new stream is created | stream_id, topic, partition_count |
| `ACF.StreamDeleted` | A stream is deleted | stream_id, message_count, reason |
| `ACF.PartitionReassigned` | A partition is reassigned to a consumer | partition_id, consumer_group, old_consumer, new_consumer |
| `ACF.ConsumerAdded` | A consumer joins a group | consumer_id, consumer_group, stream_id |
| `ACF.ConsumerRemoved` | A consumer leaves a group | consumer_id, consumer_group, reason |
| `ACF.ConsumerRebalanced` | Consumer group is rebalanced | consumer_group, partition_assignments |
| `ACF.StreamEnd` | A stream reaches its end | stream_id, last_sequence |
| `ACF.BackpressureApplied` | Backpressure is applied | stream_id, level, consumer_group, buffer_usage |
| `ACF.BackpressureOverflow` | Buffer overflow occurs | stream_id, messages_dropped, strategy |

## Cross-Cutting Concerns

### Security

Stream access requires authorization. Publishers must have publish permission. Consumers must have consume permission. Stream metadata access is restricted.

### Evidence

Every stream lifecycle operation produces an Event. Consumer position commits produce Events for audit. Backpressure Events are recorded.

### Lifecycle

Streams follow: Created → Active → Rebalancing → Archived → Deleted. Consumer groups follow: Created → Active → Rebalancing → Depleted. Stream configurations are versioned.

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
