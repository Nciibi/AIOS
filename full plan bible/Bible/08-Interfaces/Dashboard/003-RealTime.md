# AIOS Bible — Interfaces
## Dashboard — 003: Real-Time

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-DB-003 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Real-Time subsystem manages live data delivery to the Dashboard: WebSocket connections to data sources, streaming data ingestion, push updates to widgets, refresh scheduling, rate limiting, and connection lifecycle. It ensures dashboard data stays current while protecting sources from excessive query load.

## Architecture

```
Subscription (widget registers for updates)
       |
       v
Connection Manager (opens WebSocket / SSE to source)
       |
       v
Data Streaming (source pushes deltas)
       |
       v
Update Batch (accumulate deltas into batch)
       |
       v
Rate Limiter (enforce max updates per interval)
       |
       v
Widget Update (push batch to widget renderer)
       |
       v
Refresh Scheduling (periodic full re-query fallback)
       |
       v
Reconnection (on disconnect: backoff + retry)
```

## Data Model

```typescript
interface SubscriptionConfig {
  subscriptionId: string;
  widgetId: string;
  metricId: string;
  source: 'aop' | 'evs' | 'aus' | 'simulation';
  streamType: 'websocket' | 'sse' | 'polling';
  options: Record<string, unknown>;
}

interface StreamConnection {
  connectionId: string;
  source: string;
  state: 'connecting' | 'connected' | 'disconnected' | 'error';
  endpoint: string;
  connectedAt?: Timestamp;
  lastActivityAt?: Timestamp;
  reconnectAttempts: number;
}

interface UpdateBatch {
  batchId: string;
  connectionId: string;
  updates: DataPoint[];
  receivedAt: Timestamp;
  processedAt?: Timestamp;
}

interface DataPoint {
  metricId: string;
  value: number | string | boolean;
  timestamp: Timestamp;
  evidenceRef: string;
}

interface RefreshSchedule {
  widgetId: string;
  intervalSeconds: number;
  lastRefreshAt?: Timestamp;
  nextRefreshAt?: Timestamp;
  policy: 'auto' | 'manual' | 'hybrid';
}

interface ThrottlePolicy {
  maxUpdatesPerSecond: number;
  burstLimit: number;
  cooldownMs: number;
  currentRate: number;
  throttled: boolean;
}
```

## Core Concepts

### 1. Subscription Model

Widgets subscribe to real-time updates from data sources. Each subscription specifies the metric, source, and stream type. The subscription manager tracks all active subscriptions and coordinates data delivery.

### 2. Connection Management

The Connection Manager opens and maintains persistent connections (WebSocket or SSE) to data sources. It monitors connection state, handles graceful shutdown, and manages the reconnect lifecycle with exponential backoff.

### 3. Update Batching

Incoming data points are accumulated into UpdateBatch objects. Batches are processed atomically — all points in a batch are delivered together to the widget renderer to maintain consistency.

### 4. Rate Limiting

The ThrottlePolicy enforces a maximum update rate per widget and per view. When the rate exceeds limits, excess updates are queued or dropped. Rate limits protect both the dashboard client and the data sources.

### 5. Refresh Scheduling

A fallback refresh schedule ensures widgets receive updates even when streaming is interrupted. The schedule uses a hybrid policy: streaming for live data with periodic full re-queries to correct drift.

### 6. Reconnection

On disconnect, the Connection Manager executes a reconnection strategy: exponential backoff (1s, 2s, 4s, 8s, max 60s), state restoration, and missed-data catch-up from the source.

## Operations

| Operation | Description |
|-----------|-------------|
| subscribe_updates(widgetId, config) | Register a widget for real-time updates |
| connect_stream(source, endpoint) | Open a streaming connection to a data source |
| process_batch(batch: UpdateBatch) | Ingest and distribute an update batch |
| schedule_refresh(widgetId, interval) | Configure periodic refresh for a widget |
| throttle_updates(widgetId) | Apply rate limiting to widget updates |
| disconnect_stream(connectionId) | Gracefully close a streaming connection |
| reconnect(connectionId) | Execute reconnection strategy for failed connection |

## Internal Interfaces

```typescript
interface SubscriptionManager {
  subscribe(widgetId: string, config: SubscriptionConfig): Promise<string>;
  unsubscribe(subscriptionId: string): Promise<void>;
  listByWidget(widgetId: string): Promise<SubscriptionConfig[]>;
}

interface ConnectionManager {
  open(source: string, endpoint: string): Promise<StreamConnection>;
  close(connectionId: string): Promise<void>;
  getStatus(connectionId: string): Promise<StreamConnection>;
  reconnect(connectionId: string): Promise<StreamConnection>;
}

interface UpdateDistributor {
  ingest(batch: UpdateBatch): Promise<void>;
  distribute(batch: UpdateBatch): Promise<void>;
  pending(connectionId: string): Promise<number>;
}

interface ThrottleController {
  check(subscriptionId: string): Promise<boolean>;
  apply(subscriptionId: string): Promise<void>;
  getPolicy(subscriptionId: string): Promise<ThrottlePolicy>;
}
```

## Events

| Event Type | Produced When | Fields |
|-------|--------|-------------|
| DB.StreamConnected | connectionId, source, endpoint | Streaming connection established |
| DB.StreamDisconnected | connectionId, reason | Streaming connection lost |
| DB.WidgetRefreshed | widgetId, batchId, pointCount | Widget received and processed update batch |
| DB.ThrottleApplied | widgetId, rate, limit | Rate limit enforced for widget updates |
| DB.SubscriptionCreated | subscriptionId, widgetId, source | New real-time subscription registered |
| DB.SubscriptionRemoved | subscriptionId, widgetId | Subscription cancelled |
| DB.ReconnectionStarted | connectionId, attempt | Reconnection attempt initiated |
| DB.ReconnectionSucceeded | connectionId, attempt | Reconnection completed successfully |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| DB_RT_CONNECTION_FAILED | Unable to open stream connection to source | ERROR | Retry with exponential backoff; fall back to polling |
| DB_RT_STREAM_BUFFER_OVERFLOW | Update batch exceeds memory buffer limit | ERROR | Drop oldest points; log overflow event |
| DB_RT_REFRESH_RATE_EXCEEDED | Refresh interval is below minimum allowed | WARNING | Clamp to minimum interval; notify requester |
| DB_RT_RECONNECTION_TIMEOUT | All reconnection attempts exhausted | ERROR | Mark widget stale; switch to poll-only mode |
| DB_RT_SUBSCRIPTION_INVALID | SubscriptionConfig references unknown widget or metric | ERROR | Reject subscription; return validation errors |
| DB_RT_BATCH_CORRUPTED | Update batch data fails schema validation | WARNING | Skip batch; request retransmission from source |
| DB_RT_RATE_LIMIT_VIOLATION | Update rate exceeds throttle policy without cooldown | ERROR | Drop excess updates; apply cooldown period |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| DB-018 | Stale data from disconnected streams is marked stale, never shown as current | Algorithmic — freshnessCheck gates all widget updates |
| DB-019 | Refresh rate never exceeds configured minimum interval | Algorithmic — ThrottleController enforces limits per widget |
| DB-020 | Reconnection uses exponential backoff with max cap | Architectural — ConnectionManager implements capped backoff |
| DB-021 | Update batches are delivered atomically to widgets | Algorithmic — UpdateDistributor processes batches as units |
| DB-022 | No persistent connection is left dangling on view close | Architectural — SubscriptionManager cleans up on view unload |
| DB-023 | Rate limiting never drops evidence-critical data | Algorithmic — evidenceRef-bearing updates are queued, not dropped |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Real-Time subsystem owns streaming; Metrics own computation |
| R2 — Dependency Order | Subscribes to AOP, EVS, AUS streams; no circular deps |
| R3 — DRY | Stream connections shared across widgets subscribing to same source |
| R4 — Builder Pattern | RefreshSchedule uses builder for hybrid policy configuration |
| R5 — Liskov Substitution | Compliant | Stream connections are interchangeable through StreamProvider interface |
| R6 — DI over Singletons | Compliant | Connection factories are injected via stream registry |
| R9 — Deterministic | Same subscription + same source data = same widget update |
| R10 — Simpler Over Complex | Polling is the default; streaming is opt-in per widget |
| R13 — Design for Failure | Disconnect marks stale + fall back to polling; never blank |
| R14 — Paved Path | Default refresh interval (30s polling) covers most use cases |
| R15 — Open/Closed | New stream types register via StreamConnection extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Dashboard/000-Overview.md | Base dashboard architecture and refresh model |
| Bible/08-Interfaces/Dashboard/001-Metrics.md | Real-Time delivers MetricValue updates to widgets |
| Bible/08-Interfaces/Dashboard/002-Widgets.md | Widgets consume real-time data via subscriptions |
| Bible/08-Interfaces/Dashboard/005-Alerts.md | Alert subscriptions use real-time streaming |
| Bible/06-Services/ACF/000-Overview.md | ACF transports WebSocket/SSE connections |
| Bible/05-Platform/Observability/000-AOP.md | AOP provides real-time observability stream |
| Bible/08-Interfaces/UI/000-Overview.md | UI renders real-time widget updates |
| Bible/08-Interfaces/Console/000-Overview.md | Console may subscribe to real-time alert streams |
| Physics/005-Events.md | Evidence invariants — streamed data is evidence-derived |
| Physics/011-Design-DNA.md | Design DNA rules govern real-time construction |
