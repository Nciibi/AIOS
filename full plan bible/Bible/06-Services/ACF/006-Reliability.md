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

| Type | Persistence | Description |
|------|-------------|-------------|
| **Persistent** | Written to disk before ack | Survives broker restart |
| **Volatile** | Memory-only | Lost on broker restart |

### Persistent Messages

Persistent messages are written to the broker's write-ahead log (WAL) before the sender receives acknowledgment. The WAL is replicated across the Raft cluster. A message is considered durable when it is committed to the WAL on a majority of nodes.

### Volatile Messages

Volatile messages are kept in memory only. They are useful for high-throughput streaming where durability is not required. Volatile messages are lost if the broker restarts.

## Delivery Retry

ACF retries failed deliveries with exponential backoff:

| Attempt | Backoff | Total Elapsed |
|---------|---------|---------------|
| 1 | 100 ms | 100 ms |
| 2 | 1 s | 1.1 s |
| 3 | 10 s | 11.1 s |
| Dead letter | — | 11.1 s+ |

### Retry Criteria

Delivery is retried when:
- Receiver does not acknowledge within timeout
- Receiver returns a retryable error
- Transport layer error (connection lost, timeout)

### Non-Retryable Failures

Delivery is NOT retried when:
- Receiver returns a permanent error (invalid message, unauthorized)
- Message TTL has expired
- Maximum retry attempts reached

## Dead Letter Queue

The dead letter queue (DLQ) stores undeliverable messages with failure metadata:

### DLQ Message Schema

```
DeadLetterMessage {
  original_message: Message,
  failures: DeliveryFailure[],
  first_failed_at: timestamp,
  last_failed_at: timestamp,
  retry_count: int,
  dead_letter_reason: string
}

DeliveryFailure {
  attempt: int,
  endpoint: Address,
  error: string,
  error_code: string,
  timestamp: timestamp
}
```

### DLQ Operations

```
configureRetry(topic, retry_policy) → void
getRetryStatus(message_id) → RetryStatus
getDeadLetterMessages(filter?) → DeadLetterMessage[]
replayDeadLetter(dlq_message_id) → void
purgeDeadLetter(filter?) → purged_count
getDeadLetterStats() → DLQStats
```

### DLQ Retention

| Default TTL | Maximum TTL | Review Required |
|-------------|-------------|-----------------|
| 7 days | 30 days | Security Council |

After TTL expires, the dead letter message is archived. Archived DLQ messages are preserved for audit (7 years). The Security Council reviews all DLQ messages weekly.

## Reliability Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Delivery rate | 99.99% | Messages delivered / messages sent |
| Median latency | <100 ms | P50 delivery time |
| p99 latency | <1 s | P99 delivery time |
| Durability | 99.9999% | Persistent messages acknowledged |
| DLQ rate | <0.1% | Messages in DLQ / total messages |

## Reliability Operations

```
configureRetry(topic_pattern, retry_policy) → void
getRetryStatus(message_id) → RetryStatus
getDeadLetterMessages(filter?) → DeadLetterMessage[]
replayDeadLetter(dlq_message_id) → void
purgeDeadLetter(filter?) → purged_count
getReliabilityMetrics() → ReliabilityMetrics
```

## ACF Reliability Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.RetryPolicyConfigured` | Retry policy is set | topic, max_retries, backoff, timeout |
| `ACF.DeliveryAttempted` | A delivery attempt is made | message_id, attempt, endpoint, result |
| `ACF.DeliverySucceeded` | Delivery succeeds | message_id, attempt, ack_time |
| `ACF.DeliveryFailed` | Delivery fails (retryable) | message_id, attempt, error, next_retry |
| `ACF.MessageDeadLettered` | Message sent to DLQ | message_id, reason, attempts, original_target |
| `ACF.DLQReplayed` | DLQ message is replayed | dlq_message_id, new_message_id, target |
| `ACF.DLQPurged` | DLQ messages are purged | count, filter, reason |
| `ACF.ReliabilityThresholdBreached` | A reliability target is missed | metric, actual, target, time_range |

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
