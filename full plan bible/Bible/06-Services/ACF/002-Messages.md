# AIOS Bible — Services
## ACF 002 — Messages

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-002 |
| Source Laws | Law 4 — Law of Evidence, Law 5 — Law of Identity |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Every message in ACF follows a defined schema. The message consists of an envelope (routing and metadata) and a payload (the actual content). Messages are the fundamental unit of communication in AIOS — no entity communicates outside the message format.

## Message Schema

```
Message {
  envelope: Envelope,
  payload: Binary
}

Envelope {
  version: int,
  message_id: UUIDv7,
  sender: Address,
  target: Address,
  timestamp: HLC,
  auth_token: string,
  auth_type: string,
  correlation_id: UUID?,
  causation_id: UUID?,
  ttl: duration,
  reply_to: Address?,
  priority: int,
  delivery_mode: string,     // at_most_once, at_least_once, exactly_once
  flags: string[],           // durable, encrypted, audit
  extensions: map<string, any>?  // custom extensions
}
```

### Envelope Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| version | int | Yes | Message format version (currently 1) |
| message_id | UUIDv7 | Yes | Globally unique, time-sortable |
| sender | Address | Yes | ACF address of sending entity |
| target | Address | Yes | ACF address of target entity |
| timestamp | HLC | Yes | Hybrid Logical Clock timestamp |
| auth_token | string | Yes | Authentication token for sender |
| auth_type | string | Yes | Token type: session, api_key, certificate |
| correlation_id | UUID | No | Links related messages in a conversation |
| causation_id | UUID | No | Links to message that caused this one |
| ttl | duration | Yes | Time-to-live before message expires |
| reply_to | Address | No | Address for replies |
| priority | int | Yes | 0 (lowest) to 9 (highest, security-only) |
| delivery_mode | string | Yes | Delivery semantics |
| flags | string[] | No | Delivery flags |
| extensions | map | No | Custom extensions (forward-compatible) |

### Envelope Requirements

Every message MUST have:
- **sender** — Valid ACF address of the sending entity
- **target** — Valid ACF address of the receiving entity
- **auth_token** — Cryptographic token proving sender identity
- **auth_type** — Type of token presented
- **timestamp** — HLC timestamp (assigned by ACF Gateway, verified on receipt)
- **ttl** — Duration after which message expires

Messages missing any required field are rejected at the ACF Gateway with `ACF.MalformedMessage`.

## Message Size Limits

| Measurement | Default | Maximum | Configurable |
|-------------|---------|---------|-------------|
| Payload | 10 MB | 100 MB | Per channel |
| Envelope | 4 KB | 16 KB | System-wide |
| Total message | 10 MB | 100 MB | Per channel |
| Extension count | 10 | 50 | System-wide |
| Flags count | 16 | 32 | System-wide |

Messages exceeding the limit are rejected with `ACF.MessageTooLarge`. The sender receives: limit that was exceeded, actual size, and fragmentation suggestion.

## Delivery Semantics

| Semantics | Description | Retry | Dedup | Use Case |
|-----------|-------------|-------|-------|----------|
| **at-most-once** | Delivered once, no retry | None | None | Streaming metrics, logs |
| **at-least-once** | Retry until acked | 3 attempts | Required on receiver | Default, general communication |
| **exactly-once** | Deduplicated processing | 3 attempts | Required on ACF | Financial/audit Events |

### At-Least-Once Delivery

Default mode. ACF persists the message, delivers it, and waits for acknowledgment:

```
1. Message persisted to WAL
2. Delivered to receiver
3. Receiver sends ack
4. If no ack within timeout (configurable, default 30s):
   a. Retry 1: 100ms backoff
   b. Retry 2: 1s backoff
   c. Retry 3: 10s backoff
5. If all retries fail, message sent to dead letter queue
```

### Exactly-Once Delivery

Requires idempotent receivers and deduplication:

```
1. ACF assigns message_id
2. ACF persists delivery state (message_id → delivered)
3. On delivery, receiver checks message_id against processed set
4. If already processed, return ack without processing again
5. If new, process and record message_id
6. ACF maintains dedup window (configurable, default 24h)
```

## Message Operations

```
sendMessage(envelope, payload) → message_id
sendMessageWithAck(envelope, payload, timeout) → message_id, ack
receiveMessage(entity_id, timeout?) → Message
getMessageStatus(message_id) → DeliveryStatus
retryMessage(message_id) → void
deadLetterMessage(message_id, reason) → void
acknowledgeMessage(message_id) → void
rejectMessage(message_id, reason) → void
```

### getMessageStatus

```
DeliveryStatus {
  message_id: UUID,
  status: pending | queued | delivered | acknowledged | failed | dead_lettered | expired,
  delivery_attempts: DeliveryAttempt[],
  queued_at: timestamp,
  first_delivery_at?: timestamp,
  last_delivery_at?: timestamp,
  acknowledged_at?: timestamp,
  dead_letter_reason?: string
}

DeliveryAttempt {
  attempt: int,
  endpoint: Address,
  sent_at: timestamp,
  result: success | timeout | error,
  error?: string
}
```

## Message Priority

| Priority | Range | Description | Preemption |
|----------|-------|-------------|------------|
| Low | 0-2 | Background, analytics | None |
| Normal | 3-5 | Standard messages | Above low |
| High | 6-7 | Time-sensitive | Above normal |
| Critical | 8 | System operations | Above high |
| Emergency | 9 | Security/Breaking Glass | Highest |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| ACF-MSG-001 | MalformedMessage | Required envelope field missing |
| ACF-MSG-002 | MessageTooLarge | Message exceeds size limit |
| ACF-MSG-003 | InvalidAddress | Sender or target address is invalid |
| ACF-MSG-004 | TTLExpired | Message TTL expired before delivery |
| ACF-MSG-005 | UnsupportedVersion | Envelope version not supported |
| ACF-MSG-006 | DeliveryFailed | All delivery attempts failed |
| ACF-MSG-007 | DuplicateMessage | Duplicate message_id detected (exactly-once) |

## ACF Message Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.MessageSent` | Sender dispatches message | message_id, sender, target, size, priority, delivery_mode |
| `ACF.MessageAuthenticated` | Token verified | message_id, auth_type, auth_result, authentication_latency |
| `ACF.MessageAuthorized` | Route permitted | message_id, sender, target, route_rule_id |
| `ACF.MessageQueued` | Message persisted | message_id, storage_type (persistent/volatile), queue_position |
| `ACF.MessageRouted` | Target endpoint selected | message_id, target_endpoint, lb_strategy, route_latency |
| `ACF.MessageDelivered` | Message reaches receiver | message_id, receiver, delivery_attempt, delivery_latency |
| `ACF.MessageAcknowledged` | Receiver confirms | message_id, receiver, processing_time_ms |
| `ACF.MessageFailed` | Permanent delivery failure | message_id, reason, attempts, first_error, dead_lettered |
| `ACF.MessageExpired` | TTL exceeded | message_id, ttl, time_since_send, sender_notified |

## Cross-Cutting Concerns

### Security

Every message carries an auth_token and auth_type. Tokens are verified at the ACF Gateway. Messages with invalid tokens are rejected. High-priority messages (8-9) require additional authentication.

### Evidence

Every message lifecycle step produces an Event. The full message chain from send to delivery is recorded. Failed messages produce detailed failure Events.

### Lifecycle

Messages follow: Created → Authenticated → Authorized → Queued → Routed → Delivered → Acknowledged. Failed messages go: Failed → DeadLettered → Reviewed → Replayed/Aged.

### Capability Bounds

ACF Messages only transport data. They do not interpret payloads, do not enforce business rules, and do not trigger actions. Message interpretation is the responsibility of the receiving entity.

### Communication

Messages are ACF's native format. All inter-entity communication uses this message schema.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Messages are the single unit of communication |
| R2 — Dependency Order | Message schema depends on nothing |
| R3 — DRY | Envelope schema is defined once |
| R4 — Builder Pattern | Messages are built by MessageBuilders |
| R5 — Liskov | All message types use the same envelope |
| R6 — DI over Singletons | Messages are data objects; no DI needed |
| R7 — Tests Exist | Every envelope field and delivery semantic has tests |
| R8 — Tests Fast | Message serialization tests in <1ms |
| R9 — Deterministic | Same inputs always produce same serialized message |
| R10 — Simpler Over Complex | Message schema is minimal; no optional complex features |
| R11 — Refactor Over Rewrite | Envelope versions evolve with backward compatibility |
| R12 — Embrace Errors | Every rejection has a unique error code |
| R13 — Design for Failure | TTL prevents stranded messages; dead letter for failures |
| R14 — Paved Path | ACF message format is the only communication format |
| R15 — Open/Closed | New flags and delivery semantics extend without schema break |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-Architecture.md | ACF architecture — message flow through components |
| 003-Routing.md | Routing rules determine message delivery path |
| 006-Reliability.md | Delivery semantics, retries, dead letter |
| Physics/005-Events.md | Events are produced for each message step |
| Physics/009-Interaction.md | Interaction model requires all communication through ACF |
