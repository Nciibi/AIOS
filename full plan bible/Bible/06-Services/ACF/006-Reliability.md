# AIOS Bible — Services
## ACF 006 — Reliability

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-006 |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Message durability, delivery guarantees, and dead letter queues. ACF Reliability ensures that messages are not lost, are delivered to their intended recipients, and have defined failure handling paths. ACF targets 99.99% delivery rate, <100ms median latency, and <1s p99 latency.

## Durability

| Type | Persistence | Storage | Survival |
|------|-------------|---------|----------|
| **Persistent** | Written to disk before ack | Write-ahead log (WAL) | Broker restart, rack failure |
| **Volatile** | Memory only | RAM | Broker restart |

### Persistent Messages

Persistent messages are written to the broker's write-ahead log (WAL) before the sender receives acknowledgment. The WAL is replicated across the Raft cluster.

WAL characteristics:

| Aspect | Specification |
|--------|---------------|
| Storage | SSD/NVMe |
| Flush interval | 5ms (or every 1000 messages) |
| Replication | Majority of Raft nodes |
| Compression | zstd (configurable) |
| Segments | 64 MB each, auto-rotation |

A message is considered durable when committed to the WAL on a majority of nodes. The sender receives acknowledgment only after durability is confirmed.

### Volatile Messages

Volatile messages are kept in memory. Useful for high-throughput streaming where durability is not required. If the broker restarts, volatile messages are lost.

## Delivery Retry

ACF retries failed deliveries with exponential backoff:

| Attempt | Backoff | Jitter | Total Elapsed |
|---------|---------|--------|---------------|
| 1 | 100 ms | ±20 ms | 100 ms |
| 2 | 1 s | ±200 ms | 1.1 s |
| 3 | 10 s | ±2 s | 11.1 s |
| Dead letter | — | — | 11.1 s+ |

### Retry Criteria

Delivery is retried when:

- Receiver does not acknowledge within timeout (default 30s)
- Receiver returns a retryable error (error code 5xx range)
- Transport layer error (connection lost, TLS handshake failure, timeout)

### Non-Retryable Failures

Delivery is NOT retried when:

- Receiver returns a permanent error (4xx: invalid message, unauthorized)
- Message TTL has expired
- Maximum retry attempts reached (configurable, default 3)
- Target entity does not exist (entity deleted before delivery)
- Payload schema violation (receiver cannot parse the message)

### Retry Policy Configuration

```
RetryPolicy {
  max_attempts: int,              // default 3
  initial_backoff_ms: int,        // default 100
  backoff_multiplier: float,      // default 10.0
  max_backoff_ms: int,            // default 10000
  jitter_ms: int,                 // default 0.2 * backoff
  retryable_errors: string[],     // error codes that trigger retry
  timeout_ms: int                 // per-attempt timeout, default 30000
}
```

## Dead Letter Queue

The dead letter queue (DLQ) stores undeliverable messages with full failure metadata.

### DLQ Message

```
DeadLetterMessage {
  original_message: Message,
  original_envelope: Envelope,
  failures: DeliveryFailure[],
  first_failed_at: timestamp,
  last_failed_at: timestamp,
  retry_count: int,
  dead_letter_reason: string,
  dead_lettered_at: timestamp,
  dead_lettered_by: string       // component that dead-lettered
}

DeliveryFailure {
  attempt: int,
  endpoint: Address,
  error: string,
  error_code: string,
  timestamp: timestamp,
  latency_ms: int
}
```

### DLQ Operations

```
configureRetry(topic_pattern, retry_policy) → void
getRetryStatus(message_id) → RetryStatus
getDeadLetterMessages(filter?) → DeadLetterMessage[]
replayDeadLetter(dlq_message_id, new_target?) → message_id
replayAllDeadLetter(filter?) → replayed_count
purgeDeadLetter(filter?) → purged_count
getDeadLetterStats() → DLQStats
getDeadLetterMessage(dlq_message_id) → DeadLetterMessage
```

### DLQ Retention

| Default TTL | Maximum TTL | After TTL |
|-------------|-------------|-----------|
| 7 days | 30 days | Archived (cold storage, 7 years) |

### DLQ Review

The Security Council reviews all DLQ messages weekly:

| Review Criteria | Action |
|----------------|--------|
| Message can be replayed | Replay to corrected target |
| Target permanently unavailable | Archive message, notify sender |
| Malicious message | Escalate to security investigation |
| Configuration error | Fix config, replay batch |

## Reliability Targets

| Metric | Target | Measurement Period |
|--------|--------|-------------------|
| Delivery rate | 99.99% | Rolling 30 days |
| Median latency | <100ms | Rolling 1 hour |
| p99 latency | <1s | Rolling 1 hour |
| Durability (persistent) | 99.9999% | Per message |
| DLQ rate | <0.1% of total messages | Rolling 7 days |
| Downtime | <52 minutes/year | Annual |

## Reliability Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.RetryPolicyConfigured` | Retry policy set | topic_pattern, max_retries, backoff_strategy |
| `ACF.DeliveryAttempted` | Delivery attempt made | message_id, attempt, endpoint, result, latency_ms |
| `ACF.DeliverySucceeded` | Delivery succeeds | message_id, attempt, ack_time, total_latency_ms |
| `ACF.DeliveryFailed` | Delivery fails (retryable) | message_id, attempt, error, error_code, next_retry_at |
| `ACF.MessageDeadLettered` | Message sent to DLQ | message_id, reason, attempts, original_target, dlq_location |
| `ACF.DLQReplayed` | DLQ message replayed | dlq_message_id, new_message_id, replayed_by, new_target |
| `ACF.DLQPurged` | DLQ messages purged | count, oldest_message_age, reason |
| `ACF.ReliabilityThresholdBreached` | Target missed | metric_name, actual_value, target_value, time_range |
| `ACF.DLQReviewed` | DLQ review completed | reviewed_by, messages_reviewed, actions_taken |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| ACF-RL-001 | MaxRetriesExceeded | Message exceeded retry attempts |
| ACF-RL-002 | TTLExpired | Message expired before delivery |
| ACF-RL-003 | TargetUnavailable | Target entity is unavailable |
| ACF-RL-004 | DeadLetterNotFound | DLQ message not found |
| ACF-RL-005 | ReplayFailed | DLQ replay encountered error |
| ACF-RL-006 | PurgeFailed | DLQ purge encountered error |
| ACF-RL-007 | InvalidRetryPolicy | Retry policy configuration invalid |

## Cross-Cutting Concerns

### Security

DLQ messages may contain sensitive data. DLQ access is restricted to Security Council and authorized operators. DLQ replay requires authorization. Retry policy configuration requires Security Council approval.

### Evidence

Every delivery attempt produces an Event. Dead letter events are critical audit Events. Reliability metrics are continuously recorded.

### Lifecycle

Messages follow: Sent → Queued → Delivering → Delivered/Acknowledged or Failed → DeadLettered → Archived/Replayed.

### Capability Bounds

Reliability only manages delivery guarantees. It does not modify message content, does not interpret errors, and does not manage stream ordering. Reliability capabilities are limited to: persist, retry, dead letter, and replay.

### Communication

Reliability is internal to ACF. Delivery attempts are made through ACF's own infrastructure. DLQ operations use ACF messages.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Reliability does one thing: message delivery guarantees |
| R2 — Dependency Order | Reliability depends on ACF Core; no upward deps |
| R3 — DRY | Retry and DLQ policies are defined once |
| R4 — Builder Pattern | Dead letter messages include full failure context |
| R5 — Liskov | All persistence backends implement the same Store interface |
| R6 — DI over Singletons | Reliability receives ACF as injected dependency |
| R7 — Tests Exist | Every retry scenario and DLQ operation has tests |
| R8 — Tests Fast | Delivery tests complete in <20ms |
| R9 — Deterministic | Same message + same conditions always produces same delivery |
| R10 — Simpler Over Complex | Exponential backoff is simple; no adaptive algorithms |
| R11 — Refactor Over Rewrite | Reliability policies evolve via RFC |
| R12 — Embrace Errors | Every delivery failure has a unique error code |
| R13 — Design for Failure | Reliability IS the failure design |
| R14 — Paved Path | ACF Reliability is the only path for message delivery |
| R15 — Open/Closed | New persistence backends extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 002-Messages.md | Delivery semantics defined per message |
| 003-Routing.md | Routing retry policy |
| 005-Streaming.md | Stream delivery guarantees |
| 05-Platform/004-EVS.md | Event Store provides durable Event storage |
| Physics/010-Execution.md | Execution reliability requirements |
