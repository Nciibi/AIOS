# AIOS Bible â€” Domains
## Communication â€” 002: Messaging

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-COM-002 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Messaging layer handles the reliable routing and delivery of messages within AIOS â€” queue management, delivery guarantee enforcement (at-least-once, exactly-once), priority scheduling, dead-letter handling, message time-to-live, batching, and deduplication. It transforms the parsed envelopes from the Protocols layer into confirmed deliveries, ensuring that every message reaches its intended recipient with the promised reliability level.

Messages enter the system through the ingress queue, are classified by priority, routed according to the routing table, delivered through the appropriate channel adapter, and acknowledged by the recipient. Undeliverable messages flow into the dead-letter queue with full context for later analysis. Duplicate messages are detected by deduplication key before they enter the delivery pipeline.

## Architecture

```
Ingress (from Protocols layer)
    |
    v
+---------------------+
| Ingress Queue       |  Classifies by priority, assigns TTL
| (queue_message)     |  Applies deduplication check
+---------------------+
    |
    v
+---------------------+
| Router              |  Consults routing table for target Worker/channel
| (route_message)     |  Emits Comm.MessageRouted on success
+---------------------+
    |
    v
+---------------------+
| Delivery Engine     |  Selects delivery guarantee strategy
| (deliver_message)   |  Retries transparently on transient failure
+---------------------+
    |
    v
+---------+           +---------------------+
| Ack     |  OR  FAIL | Dead Letter Queue   |
| Received|---------->| (handle_dead_letter)|
+---------+           +---------------------+
                           |
                           v
                      Analysis / Manual retry / TTL expiry
```

Each stage is observable via events. The routing table is dynamic â€” Workers register and deregister as they come online. Message ordering is preserved within a single priority level per sender queue. Cross-priority ordering is not guaranteed; higher priority messages may jump ahead.

## Data Model

```typescript
interface MessageQueue {
  queueId: string;
  name: string;
  type: 'ingress' | 'outgress' | 'dead_letter' | 'retry';
  priority: MessagePriority;
  depth: number;
  maxDepth: number;
  ttlConfig: TTLConfig;
  deadLetterPolicy: DeadLetterPolicy;
  batchingConfig?: BatchingConfig;
  createdAt: number;
  messageCount: number;
  oldestMessageAgeMs: number;
}

interface DeliveryGuarantee {
  mode: 'at_least_once' | 'exactly_once' | 'at_most_once';
  maxRetries: number;
  retryDelayMs: number;
  retryBackoffMultiplier: number;
  ackTimeoutMs: number;
  dedupRequired: boolean;
  deadLetterAfterRetries: boolean;
}

interface MessagePriority {
  level: 'critical' | 'high' | 'normal' | 'low' | 'background';
  weight: number;
  preemptLower: boolean;
  maxQueueTimeMs: number;
}

interface DeadLetterPolicy {
  maxRetries: number;
  maxDeadLetterDepth: number;
  ttlOnDeadLetterMs: number;
  notifyOnDeadLetter: boolean;
  notifyChannel?: string;
  autoRetryIntervalMs?: number;
}

interface TTLConfig {
  messageTtlMs: number;
  queueTtlMs: number;
  extendedTtlOnRetry: boolean;
  ttlExtensionPerRetryMs: number;
  actionOnExpiry: 'discard' | 'dead_letter' | 'notify_sender';
}

interface DedupKey {
  key: string;
  algorithm: DedupAlgorithm;
  ttlMs: number;
  scope: 'global' | 'sender' | 'queue';
}

interface BatchingConfig {
  batchSize: number;
  batchWindowMs: number;
  maxBatchBytes: number;
  flushOnPriority: boolean;
}

type DedupAlgorithm = 'exact_hash' | 'content_hash' | 'message_id' | 'correlation_id';
type DeliveryStatus = 'queued' | 'routing' | 'delivering' | 'delivered' | 'failed' | 'dead_lettered' | 'expired';
type QueueOverflowAction = 'reject_newest' | 'reject_oldest' | 'dead_letter_oldest' | 'block_ingress';
```

## Core Concepts / Operations

| Operation | Preconditions | Postconditions |
|-----------|--------------|----------------|
| queue_message | Envelope is parsed and normalized | Message added to ingress queue; `Comm.MessageQueued` emitted |
| route_message | Queue depth within limit, routing table populated | Target channel/Worker resolved; `Comm.MessageRouted` emitted |
| deliver_message | Route resolved, channel adapter online | Message sent; ack or nack received; delivery status updated |
| handle_dead_letter | Max retries exceeded or fatal delivery error | Message moved to dead-letter queue with full metadata preserved |
| deduplicate | Dedup key extracted from envelope | Duplicate suppressed with `Comm.DuplicateSuppressed`; original delivery confirmed |
| requeue_dead_letter | Dead letter message identified for retry | Message moved back to ingress queue with incremented retry count |
| expire_messages | TTL threshold crossed | Messages removed from queue; expiry event emitted; policy action applied |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| IMessageQueue | Messaging Module | Protocols (001), Collaboration (003) | ACF event |
| IRoutingTable | Messaging Module | Delivery Engine | Internal |
| IDeliveryEngine | Messaging Module | Channel adapters | ACF sync |
| IDeadLetterManager | Messaging Module | Admin console, NotificationDispatcher | ACF query |
| IDedupCache | Messaging Module | Ingress Queue | Internal |

## Events

| COM.EventType |  Produced When | Fields |
|-----------|--------------|--------|
| COM.MessageQueued |  Message enters ingress queue | message_id, queue_id, priority, ttl_ms, queue_depth_after, dedup_key |
| COM.MessageRouted |  Route is resolved and target is selected | message_id, source_queue, target_worker, target_channel, routing_duration_ms |
| COM.MessageDelivered |  Recipient acknowledges delivery | message_id, delivery_mode, retry_count, ack_latency_ms, channel_type |
| COM.MessageDeliveryFailed |  Delivery fails after all retries exhausted | message_id, attempt_count, last_error, total_duration_ms, dead_letter_route |
| COM.MessageDeadLettered |  Message moved to dead-letter queue | message_id, source_queue, reason, retry_count, ttl_at_death_ms, metadata |
| COM.MessageExpired |  TTL exceeded, message removed from queue | message_id, queue_id, ttl_ms, age_at_expiry_ms, action_taken |
| COM.DuplicateSuppressed |  Duplicate message detected and suppressed | message_id, dedup_key, algorithm, original_delivery_id, suppression_type |
| COM.QueueDepthWarning |  Queue depth exceeds warning threshold | queue_id, depth, max_depth, oldest_message_age_ms, action_recommended |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COM-MSG-001 | Queue full â€” depth exceeds configured maximum | Critical | Apply QueueOverflowAction; reject or dead-letter oldest; emit alert |
| COM-MSG-002 | Routing table miss â€” no target for message | Error | Dead-letter with unknown_target reason; notify administrator |
| COM-MSG-003 | Delivery timeout â€” ack not received within window | Warning | Retry with backoff up to maxRetries; dead-letter on exhaustion |
| COM-MSG-004 | Dead-letter queue overflow â€” depth exceeds max | Critical | Block further dead-letter moves; alert operator; oldest entries archived |
| COM-MSG-005 | TTL expiry during retry â€” message age exceeds limit | Warning | Apply TTL action (discard/dead-letter/notify); emit expiry event |
| COM-MSG-006 | Dedup cache unavailable â€” cannot verify duplicate | Warning | Bypass dedup for this message; log degraded state; attempt cache restore |
| COM-MSG-007 | Delivery guarantee downgraded â€” exactly-once not feasible | Warning | Accept at-least-once delivery; log downgrade with reason and duration |
| COM-MSG-008 | Batch assembly timeout â€” partial batch delivered | Low | Deliver partial batch; flush remaining messages in next window |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COM-MSG-I-001 | Delivery guarantee mode is enforced for every message | Delivery engine selects strategy based on guarantee metadata; at-least-once always retries |
| COM-MSG-I-002 | Message ordering is preserved within priority level per sender | Queue enforces FIFO per (priority, sender_id) partition; cross-priority reordering allowed |
| COM-MSG-I-003 | Duplicate suppression is at-most-once per dedup key within TTL window | Dedup cache rejects exact matches; Comm.DuplicateSuppressed emitted |
| COM-MSG-I-004 | Every dead-lettered message retains full original envelope and failure chain | Dead-letter store preserves message, retries, errors, and routing history |
| COM-MSG-I-005 | Routing table is eventually consistent â€” stale entries tolerated but flagged | Stale route detection runs on schedule; stale entries serve traffic until verified offline |
| COM-MSG-I-006 | Message TTL is monotonic â€” retries never extend beyond original + configured extension | TTL tracker enforces absolute expiry; ttlExtensionPerRetryMs is bounded |


## Cross-Cutting Concerns

### Security

Communication operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Communication emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Communication instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Communication declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 (Modulsingularity) | Queuing, routing, delivery, dedup, dead-letter are separate modules with clear boundaries |
| R2 (Capsule) | Each message is a sealed capsule with immutable ID, priority, TTL, and delivery history |
| R3 (DRY) | Routing table is the single source of truth for target resolution; duplicates are detected by dedup |
| R4 (Builder) | Delivery state machine builds progressively through queued -> routed -> delivering -> delivered |
| R5 (Liskov Substitution) | All delivery guarantees implement the same IDeliveryStrategy interface; interchangeable per message |
| R6 (DI over Singletons) | Queue stores and delivery engines are injected; no global singleton access pattern |
| R9 (Deterministic) | Same message ID + same routing table state yields identical route resolution |
| R10 (Simpler Over Complex) | Delivery state machine is linear with a single failure branch to dead-letter; no graph |
| R13 (Design for Failure) | Dead-letter queue preserves every failed message; no silent data loss |
| R14 (Paved Path) | Single paved path: queue -> route -> deliver -> ack/dead-letter; all deviations logged |
| R15 (Open/Closed) | New delivery guarantee modes added by implementing IDeliveryStrategy; core unchanged |

| R1 | Compliant |
| R2 | Compliant |
| R3 | Compliant |
| R4 | Compliant |
| R5 | Compliant |
| R6 | Compliant |
| R9 | Compliant |
| R10 | Compliant |
| R13 | Compliant |
| R14 | Compliant |
| R15 | Compliant |
## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Communication/000-Overview.md | Overview â€” Messaging is the reliable delivery backbone for all communication |
| Bible/07-Domains/Communication/001-Protocols.md | Upstream â€” Consumes parsed MessageEnvelopes from the Protocols layer |
| Bible/07-Domains/Communication/003-Collaboration.md | Parallel â€” Collaboration sessions generate messages that flow through messaging |
| Bible/06-Services/ACF/001-Architecture.md | Transport â€” ACF carries messages between messaging module and Workers |
| Bible/06-Services/ACF/002-Messages.md | Messages â€” ACF message format aligns with Messaging envelope structure |
| Bible/06-Services/ACF/006-Reliability.md | Reliability â€” Delivery guarantees and dead-letter policies align with ACF reliability model |
| Physics/005-Events.md | Evidence â€” Every queue operation, delivery, and failure produces an Event |
| Physics/007-Capabilities.md | Capabilities â€” Message throughput and depth are bounded by capability profiles |
| Physics/009-Interaction.md | Interaction â€” Messaging implements reliable human-AIOS message exchange |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” Core principles for reliable messaging |
