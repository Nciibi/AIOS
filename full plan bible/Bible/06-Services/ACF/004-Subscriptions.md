# AIOS Bible — Services
## ACF 004 — Subscriptions

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-004 |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Pub/sub subscriptions and Event streams. Subscriptions allow entities to receive messages that match a topic or pattern without knowing the publisher. Publishers broadcast to topics; ACF delivers to all matching subscribers. Subscriptions are the foundation for Event-driven communication and stream processing.

## Subscription Model

```
Publisher ──► Topic ──► ACF ──► Subscriber A
                          ├──► Subscriber B
                          └──► Subscriber C
```

- **Publisher** sends messages to a topic
- **Topic** is a named channel (hierarchical)
- **Subscriber** registers interest in a topic or pattern
- **ACF** delivers all matching messages to subscribers

## Subscription Types

| Type | Persistence | Description |
|------|-------------|-------------|
| **Durable** | Persist across restarts | Subscriber receives messages even after restart |
| **Volatile** | Lost on restart | Subscriber receives messages only while connected |
| **Filtered** | As configured | Subscriber provides a filter predicate |
| **Batch** | As configured | Accumulate messages before delivery |
| **Exclusive** | Single consumer | Only one subscriber receives each message |

## Topics

### Hierarchical Topics

Topics use dot-separated hierarchy:

```
academy.knowledge.accepted
academy.knowledge.rejected
lifecycle.state.changed
lifecycle.entity.created
security.auth.authenticated
security.auth.authorized
```

### Wildcard Support

| Wildcard | Matches |
|----------|---------|
| `*` | Exactly one level | `academy.knowledge.*` matches `academy.knowledge.accepted` |
| `**` | Zero or more levels | `academy.**` matches all academy topics |

### Topic Rules

- Topics are case-sensitive
- Maximum depth: 8 levels
- Maximum topic length: 256 characters
- Wildcards only at end of pattern (not in middle)

## Subscription Operations

```
subscribe(entity_id, topic_pattern, subscription_type, config) → subscription_id
unsubscribe(subscription_id) → void
publish(topic, message) → published_count
listSubscriptions(entity_id) → Subscription[]
listSubscribers(topic) → Subscriber[]
getSubscriptionStatus(subscription_id) → SubscriptionStatus
updateSubscription(subscription_id, updates) → void
```

### Subscription Lifecycle

```
Requested → Active → Paused → Reconnecting → Unsubscribed → Archived
```

| State | Description |
|-------|-------------|
| **Requested** | Subscription requested, pending approval |
| **Active** | Subscriber is receiving messages |
| **Paused** | Messages are buffered, not delivered |
| **Reconnecting** | Subscriber is offline, backlog accumulating |
| **Unsubscribed** | Subscription ended by subscriber |
| **Archived** | Subscription record preserved for audit |

## Filtered Subscriptions

Subscribers can provide a filter predicate that evaluates against message metadata and payload. Supported filter operations:

| Operation | Description |
|-----------|-------------|
| **field == value** | Field equality |
| **field != value** | Field inequality |
| **field in [values]** | Field in list |
| **field matches pattern** | Regex match |
| **field exists** | Field presence check |
| **payload.path == value** | Nested payload field access |

## Batch Subscriptions

Batch subscriptions accumulate messages and deliver them in batches:

| Parameter | Default | Description |
|-----------|---------|-------------|
| **max_batch_size** | 100 | Maximum messages per batch |
| **max_batch_interval** | 5 seconds | Maximum wait time before delivery |
| **max_batch_bytes** | 10 MB | Maximum batch size in bytes |

## ACF Subscription Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.SubscriptionCreated` | A new subscription is created | subscription_id, entity_id, topic_pattern, type |
| `ACF.SubscriptionActivated` | Subscription starts receiving | subscription_id, activated_at |
| `ACF.SubscriptionPaused` | Subscription is paused | subscription_id, reason |
| `ACF.SubscriptionUnsubscribed` | Subscription ends | subscription_id, reason |
| `ACF.MessagePublished` | A message is published to a topic | topic, message_id, subscriber_count |
| `ACF.SubscriptionDelivered` | A message is delivered to subscriber | subscription_id, message_id, delivery_attempt |
| `ACF.BackpressureApplied` | Slow subscriber causes backpressure | subscription_id, buffer_size, limit |

## Cross-Cutting Concerns

### Security

Subscriptions require authorization — an entity may only subscribe to topics it has permission for. Publishing to a topic requires publish authorization. Subscription authorization is verified at creation time.

### Evidence

Every subscription operation produces an Event. Published messages are tracked. Delivery Events confirm subscriber receipt.

### Lifecycle

Subscriptions follow the defined lifecycle. Topics follow: Created → Active → Archived → Deleted. Subscription schemas are versioned.

### Capability Bounds

Subscriptions only manage pub/sub message delivery. They do not transform messages, do not store messages long-term (EVS does), and do not interpret message content.

### Communication

Subscriptions are entirely within ACF. Publishers send to topics via ACF messages. Subscribers receive through ACF delivery channels.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Subscriptions do one thing: pub/sub message delivery |
| R2 — Dependency Order | Subscriptions depend on ACF Core; no upward deps |
| R3 — DRY | Topic definitions are stored once |
| R4 — Builder Pattern | Subscriptions are built by SubscriptionBuilders |
| R5 — Liskov | All subscription types implement the same Subscription interface |
| R6 — DI over Singletons | Subscription Manager receives ACF as injected dep |
| R7 — Tests Exist | Every subscription type and topic pattern has tests |
| R8 — Tests Fast | Subscription operations complete in <5ms |
| R9 — Deterministic | Same topic + same subscribers always produces same delivery |
| R10 — Simpler Over Complex | Hierarchical topics are simple; no complex routing |
| R11 — Refactor Over Rewrite | Topic structure evolves via versioned updates |
| R12 — Embrace Errors | Every subscription failure has a unique error code |
| R13 — Design for Failure | Backpressure protects publishers from slow subscribers |
| R14 — Paved Path | ACF Subscriptions are the only path for pub/sub delivery |
| R15 — Open/Closed | New subscription types extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-Architecture.md | ACF architecture — Subscription Manager component |
| 002-Messages.md | Messages published to topics use the message schema |
| 005-Streaming.md | Streams extend subscriptions for ordered message sequences |
| 006-Reliability.md | Delivery guarantees for subscriptions |
| Physics/005-Events.md | Events are published to topics |
