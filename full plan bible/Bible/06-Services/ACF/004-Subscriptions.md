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
Publisher ──► Topic ──► ACF ──► Subscriber A (durable)
                          ├──► Subscriber B (filtered: severity == "critical")
                          ├──► Subscriber C (batch: max 100, max 5s)
                          └──► Subscriber D (volatile)
```

- **Publisher** sends messages to a topic
- **Topic** is a named channel (hierarchical naming)
- **Subscriber** registers interest in a topic or pattern
- **ACF** delivers all matching messages to subscribers

## Subscription Types

| Type | Persistence | Delivery | Use Case |
|------|-------------|----------|----------|
| **Durable** | Persist across restarts | Guaranteed delivery | Critical Event consumers |
| **Volatile** | Lost on restart | Best-effort | Real-time dashboards |
| **Filtered** | As configured | Filtered delivery | Selective consumption |
| **Batch** | As configured | Batched delivery | Bulk processing |
| **Exclusive** | Single consumer | Single delivery | Exactly-once processing |

### Durable Subscriptions

Durable subscriptions persist subscription state and message delivery state. If the subscriber restarts, it resumes from the last acknowledged message. Durable subscriptions are identified by a unique subscription name.

### Volatile Subscriptions

Volatile subscriptions exist only while the subscriber is connected. If the subscriber disconnects, the subscription is lost. Messages published while the subscriber is disconnected are not replayed.

### Filtered Subscriptions

Subscribers provide a filter predicate. Only messages matching the predicate are delivered. Filter evaluation happens at the broker, reducing network traffic.

### Batch Subscriptions

Messages are accumulated and delivered in batches:

| Parameter | Default | Description |
|-----------|---------|-------------|
| max_batch_size | 100 | Maximum messages per batch |
| max_batch_interval | 5s | Maximum wait time |
| max_batch_bytes | 10 MB | Maximum batch byte size |

## Topics

### Hierarchical Topics

Topics use dot-separated hierarchy:

```
academy.knowledge.accepted
academy.knowledge.rejected
academy.knowledge.revised

lifecycle.state.changed
lifecycle.entity.created
lifecycle.entity.completed

security.auth.authenticated
security.auth.authorized
security.auth.denied

system.session.created
system.session.destroyed
```

### Wildcard Support

| Wildcard | Description | Matches | Does Not Match |
|----------|-------------|---------|----------------|
| `*` | Exactly one level | `academy.knowledge.*` → `academy.knowledge.accepted` | `academy.knowledge.deep.accepted` |
| `**` | Zero or more levels | `academy.**` → `academy.knowledge.accepted`, `academy` | Everything outside academy |

### Topic Rules

- Topics are case-sensitive
- Maximum depth: 8 levels
- Maximum topic length: 256 characters
- Wildcards only at end of pattern
- Topics must start with a domain name (e.g., `academy`, `lifecycle`, `security`)

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
Requested → Validating → Active → Paused → Reconnecting → Unsubscribed → Archived
```

| State | Description |
|-------|-------------|
| **Requested** | Subscription received, pending validation |
| **Validating** | Checking authorization and topic validity |
| **Active** | Subscriber is receiving messages |
| **Paused** | Messages buffered but not delivered |
| **Reconnecting** | Subscriber offline, backlog accumulating |
| **Unsubscribed** | Subscription ended by subscriber |
| **Archived** | Subscription record preserved for audit |

### Subscription Config

```
SubscriptionConfig {
  type: "durable" | "volatile" | "filtered" | "batch" | "exclusive",
  filter?: FilterPredicate,
  batch_config?: BatchConfig,
  auto_ack: bool,           // automatically acknowledge
  max_unacked_messages: int,  // backpressure threshold
  dead_letter_topic: string?  // where undelivered messages go
}
```

## Filtered Subscriptions

Filter predicates support:

| Operation | Syntax | Description |
|-----------|--------|-------------|
| Equality | `field == value` | Exact match |
| Inequality | `field != value` | Not equal |
| Numeric | `field > value`, `field >= value` | Numeric comparison |
| Set membership | `field in [a, b, c]` | In list |
| Regex | `field matches "pattern"` | Pattern match |
| Existence | `field exists` | Field present |
| Logical AND | `cond1 and cond2` | Both true |
| Logical OR | `cond1 or cond2` | Either true |
| Logical NOT | `not cond` | Negation |
| Payload path | `payload.path.to.value == x` | Nested access |

## ACF Subscription Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.SubscriptionCreated` | New subscription created | subscription_id, entity_id, topic_pattern, type, config |
| `ACF.SubscriptionActivated` | Subscription starts receiving | subscription_id, activated_at |
| `ACF.SubscriptionPaused` | Subscription paused | subscription_id, reason, buffer_size |
| `ACF.SubscriptionResumed` | Subscription resumes | subscription_id, buffered_messages_delivered |
| `ACF.SubscriptionUnsubscribed` | Subscription ends | subscription_id, reason, messages_delivered |
| `ACF.MessagePublished` | Message published to topic | topic, message_id, subscriber_match_count |
| `ACF.SubscriptionDelivered` | Message delivered to subscriber | subscription_id, message_id, delivery_attempt, latency |
| `ACF.BackpressureApplied` | Slow subscriber throttled | subscription_id, buffer_size, buffer_limit, consumer_slow |
| `ACF.FilterEvaluated` | Filter predicate evaluated | subscription_id, message_id, filter_result |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| ACF-SUB-001 | SubscriptionNotFound | No subscription with the given ID |
| ACF-SUB-002 | TopicNotFound | No subscribers for this topic |
| ACF-SUB-003 | InvalidTopic | Topic name violates naming rules |
| ACF-SUB-004 | InvalidFilter | Filter predicate syntax error |
| ACF-SUB-005 | UnauthorizedTopic | Entity not authorized for topic |
| ACF-SUB-006 | QuotaExceeded | Entity has max subscriptions |
| ACF-SUB-007 | DuplicateSubscription | Subscription already exists for this topic/entity |

## Cross-Cutting Concerns

### Security

Subscriptions require authorization — an entity may only subscribe to topics it has permission for. Publishing requires publish authorization. Subscription authorization is verified at creation time.

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
