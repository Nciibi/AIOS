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
  flags: string[]
}
```

### Envelope Fields

| Field | Required | Description |
|-------|----------|-------------|
| **version** | Yes | Message format version (currently 1) |
| **message_id** | Yes | Globally unique, time-sortable ID |
| **sender** | Yes | ACF address of the sending entity |
| **target** | Yes | ACF address of the receiving entity |
| **timestamp** | Yes | Hybrid Logical Clock timestamp |
| **auth_token** | Yes | Authentication token for sender |
| **auth_type** | Yes | Token type (session, api_key, certificate) |
| **correlation_id** | No | Links related messages in a conversation |
| **causation_id** | No | Links to the message that caused this one |
| **ttl** | Yes | Time-to-live — message expires after this |
| **reply_to** | No | Address to send replies to |
| **priority** | Yes | 0 (lowest) to 9 (highest, security-only) |
| **flags** | No | Delivery flags (durable, encrypted, audit) |

### Envelope Requirements

Every message MUST have:
- **sender** — Valid ACF address of the sender
- **target** — Valid ACF address of the target
- **auth_token** — Cryptographic token proving sender identity
- **timestamp** — HLC timestamp assigned by ACF Gateway

Messages missing any required field are rejected at the ACF Gateway with `ACF.MalformedMessage`.

## Message Size Limit

| Scope | Default | Maximum | Configurable? |
|-------|---------|---------|---------------|
| Payload size | 10 MB | 100 MB | Per-channel |
| Envelope size | 4 KB | 16 KB | System-wide |
| Total message | 10 MB | 100 MB | Per-channel |

Messages exceeding the limit are rejected with `ACF.MessageTooLarge`. The sender receives the limit and suggested fragmentation strategy.

## Delivery Semantics

| Semantics | Description | Use Case |
|-----------|-------------|----------|
| **at-most-once** | Message is delivered once, no retry | Streaming, metrics |
| **at-least-once** | Message is retried until acknowledged | Default, general communication |
| **exactly-once** | Deduplication ensures single processing | Financial/audit Events |

### At-Least-Once Delivery

Default delivery mode. ACF persists the message, delivers it, and waits for acknowledgment. If acknowledgment is not received within the timeout, ACF retries (up to 3 attempts). After 3 attempts, the message goes to the dead letter queue.

### Exactly-Once Delivery

Requires idempotent receivers and deduplication. ACF assigns a unique message_id and deduplicates on the receiver side. Receivers must implement idempotency. Exactly-once is used for financial transactions, audit Events, and lifecycle transitions.

## Message Operations

```
sendMessage(envelope, payload) → message_id
receiveMessage(timeout?) → Message
getMessageStatus(message_id) → DeliveryStatus
retryMessage(message_id) → void
deadLetterMessage(message_id, reason) → void
acknowledgeMessage(message_id) → void
```

## ACF Message Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.MessageSent` | Sender dispatches message | message_id, sender, target, size, priority |
| `ACF.MessageAuthenticated` | Token is verified | message_id, auth_type, auth_result |
| `ACF.MessageAuthorized` | Route is permitted | message_id, sender, target, route_rule |
| `ACF.MessageQueued` | Message is persisted | message_id, storage_location |
| `ACF.MessageRouted` | Target endpoint selected | message_id, target_endpoint, lb_strategy |
| `ACF.MessageDelivered` | Message reaches receiver | message_id, receiver, delivery_attempt |
| `ACF.MessageAcknowledged` | Receiver confirms processing | message_id, receiver, processing_time |
| `ACF.MessageFailed` | Delivery fails permanently | message_id, reason, attempts, dead_letter |
| `ACF.MessageExpired` | TTL exceeded | message_id, ttl, sender_notified |

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
