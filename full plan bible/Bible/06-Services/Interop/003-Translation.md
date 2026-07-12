# AIOS Bible — Services
## 003 — Message Translation & Routing

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services/Interop |
| Document ID | AIOS-BBL-006-IOP-003 |
| Source Laws | Law 3 — Law of Communication, Law 5 — Law of Identity, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Translate messages between different protocols and contract versions, route messages based on contract references, and manage subscription delivery. The Translation layer ensures that entities using different protocol versions, serialization formats, or contract versions can communicate reliably through automatic translation and deterministic routing.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Message Translation & Routing                  │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                  Translation Engine                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │ Field Mapping│  │ Type Coercion│  │ Default Value │  │  │
│  │  │ Engine       │  │ Engine       │  │ Injector     │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  └─────────────────────────┬──────────────────────────────┘  │
│                            │                                  │
│  ┌─────────────────────────▼──────────────────────────────┐  │
│  │                  Routing Engine                         │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │ Routing Table│  │ Subscription │  │ Delivery     │  │  │
│  │  │ Manager      │  │ Manager      │  │ Dispatcher   │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                            │                                  │
│  ┌─────────────────────────▼──────────────────────────────┐  │
│  │                  Translation Cache                      │  │
│  │  (cached translations, routing table snapshots)         │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│                 IOP Translation & Routing Layer                │
└───────────────────────────────────────────────────────────────┘
```

## Data Model

```typescript
interface TranslationRule {
  ruleId: string;
  sourceContractId: string;
  targetContractId: string;
  sourceVersion: string;
  targetVersion: string;
  fieldMappings: FieldMapping[];
  typeCoercions: TypeCoercion[];
  defaultValues: DefaultValue[];
  condition?: TranslationCondition;
  priority: number;
}

interface FieldMapping {
  sourceField: string;
  targetField: string;
  transformation?: 'direct' | 'concat' | 'split' | 'transform';
  transformFunction?: string;
  required: boolean;
}

interface TypeCoercion {
  field: string;
  sourceType: string;
  targetType: string;
  strategy: 'implicit' | 'explicit' | 'strict';
  fallbackValue?: unknown;
}

interface DefaultValue {
  field: string;
  value: unknown;
  condition?: 'always' | 'if-missing' | 'if-null';
}

interface TranslationCondition {
  field: string;
  operator: 'equals' | 'not-equals' | 'exists' | 'matches';
  value: unknown;
}

interface MessageTranslator {
  translatorId: string;
  rules: TranslationRule[];
  translate: (payload: unknown, context: TranslationContext) => Promise<TranslationResult>;
  compile: (rules: TranslationRule[]) => void;
}

interface TranslationContext {
  sourceProtocol: string;
  targetProtocol: string;
  sourceContractId: string;
  targetContractId: string;
  sourceVersion: string;
  targetVersion: string;
  options: TranslationOptions;
}

interface TranslationOptions {
  strictMode: boolean;
  preserveUnknownFields: boolean;
  logWarnings: boolean;
  maxTranslationDepth: number;
}

interface TranslationResult {
  translated: boolean;
  output: unknown;
  warnings: string[];
  appliedRules: string[];
  duration: number;
}

interface RouterConfig {
  routerId: string;
  routingTable: RoutingTable;
  defaultRoute?: RouteEntry;
  fallbackBehavior: 'reject' | 'dead-letter' | 'broadcast';
  maxRetries: number;
  retryDelayMs: number;
}

interface RoutingTable {
  tableId: string;
  entries: RouteEntry[];
  version: number;
  lastUpdated: Timestamp;
}

interface RouteEntry {
  routeId: string;
  contractId: string;
  targetEntityId: string;
  protocol: string;
  endpoint: string;
  priority: number;
  filters: RouteFilter[];
  status: 'active' | 'draining' | 'suspended';
}

interface RouteFilter {
  field: string;
  operator: string;
  value: unknown;
}

interface SubscriptionDelivery {
  subscriptionId: string;
  entityId: string;
  topic: string;
  contractId: string;
  deliveryMode: 'at-most-once' | 'at-least-once' | 'exactly-once';
  retryPolicy: RetryPolicy;
  lastDelivered: Timestamp;
  deliveryCount: number;
}

interface RetryPolicy {
  maxAttempts: number;
  backoffMs: number;
  backoffMultiplier: number;
  maxBackoffMs: number;
}

interface TranslationCache {
  cacheId: string;
  rules: Map<string, CachedTranslation>;
  routingSnapshots: Map<string, CachedRoute>;
  ttlMs: number;
  hit: (key: string) => Promise<CachedTranslation | null>;
  set: (key: string, value: CachedTranslation, ttlMs?: number) => Promise<void>;
  invalidate: (pattern: string) => Promise<void>;
}

interface CachedTranslation {
  inputHash: string;
  output: unknown;
  appliedRules: string[];
  cachedAt: Timestamp;
  expiresAt: Timestamp;
}

interface CachedRoute {
  contractId: string;
  targetEntityId: string;
  route: RouteEntry;
  cachedAt: Timestamp;
  expiresAt: Timestamp;
}
```

## Core Concepts / Operations

### Message Translation Rules

Translation rules define how fields are mapped from a source contract version to a target contract version. Rules support direct field mapping (same name, same type), field renaming, field splitting (one source field to multiple target fields), field concatenation (multiple source fields to one target field), and custom transformation functions. Rules are evaluated in priority order; the first matching rule is applied.

### Contract Version Translation

When a message references a contract version different from the receiver's supported version, the translator applies version migration rules:
- v1 → v2: Field additions (inject defaults), field removals (drop if not required), field renames (apply mapping), type changes (apply coercion).
- v2 → v1: Reverse mapping — drop unknown fields, coerce types to narrower constraints, strip new fields.
- Multiple step translation is supported (v1 → v3 via v2 intermediate) with configurable depth limit.

### Cross-Protocol Translation

Messages are translated between protocol formats (gRPC → REST, JSON → Protobuf) by combining format conversion (via Protocol Adapters) with field mapping (via Translation Rules). The translation engine first converts the payload format, then applies field-level mappings for the target contract version, and finally validates against the target contract schema.

### Message Routing by Contract Reference

The Routing Engine consults the Routing Table to determine the target entity for a given contract reference. Routes are resolved by contract ID and optional filters. When multiple routes match, the highest-priority active route is selected. Routes can be in draining status to allow graceful connection teardown.

### Subscription Management and Delivery Guarantees

Subscriptions associate an entity with a topic and contract ID. Delivery guarantees are specified per subscription:
- At-most-once: Fire and forget. No retry on failure.
- At-least-once: Retry on failure per retry policy. May deliver duplicates.
- Exactly-once: Deduplication via message IDs. Guaranteed single delivery.

### Translation Cache for Performance

Frequently used translations are cached to avoid repeated compilation and field mapping. The cache uses a hash of the input payload and the applied rule set as the key. Cache entries have a configurable TTL and are invalidated when the relevant translation rules or routing table change.

### Routing Table Updates on Endpoint Changes

When an endpoint registers, drains, or goes offline, the Routing Table is updated. Updates trigger cache invalidation for affected routes and emit routing table change events. During updates, in-flight messages complete using the previous routing table; new messages use the updated table.

## Internal Interfaces

```typescript
interface TranslationEngine {
  registerRules(rules: TranslationRule[]): Promise<void>;
  unregisterRules(ruleIds: string[]): Promise<void>;
  translate(payload: unknown, context: TranslationContext): Promise<TranslationResult>;
  compileRules(source: string, target: string, contractId: string): Promise<TranslationRule[]>;
}

interface RoutingEngine {
  registerRoute(entry: RouteEntry): Promise<void>;
  unregisterRoute(routeId: string): Promise<void>;
  resolveRoute(contractId: string, filters?: RouteFilter[]): Promise<RouteEntry | null>;
  updateRoutingTable(table: RoutingTable): Promise<void>;
}

interface SubscriptionManager {
  createSubscription(subscription: SubscriptionDelivery): Promise<void>;
  removeSubscription(subscriptionId: string): Promise<void>;
  deliver(topic: string, contractId: string, payload: unknown): Promise<DeliveryResult>;
  getSubscription(subscriptionId: string): Promise<SubscriptionDelivery>;
}

interface CacheManager {
  get(key: string): Promise<CachedTranslation | null>;
  set(key: string, value: CachedTranslation, ttl?: number): Promise<void>;
  invalidate(pattern: string): Promise<void>;
  clear(): Promise<void>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `IOP.Tr.TranslationRuleApplied` | ruleId, sourceContract, targetContract | Translation rule matched and applied |
| `IOP.Tr.VersionTranslated` | translatorId, sourceVersion, targetVersion | Contract version translation completed |
| `IOP.Tr.CrossProtocolTranslated` | translatorId, sourceProtocol, targetProtocol | Cross-protocol translation completed |
| `IOP.Tr.MessageRouted` | routeId, contractId, targetEntityId | Message routed to target entity |
| `IOP.Tr.SubscriptionDelivered` | subscriptionId, topic, entityId | Message delivered to subscriber |
| `IOP.Tr.DeliveryFailed` | subscriptionId, topic, entityId, reason, attempt | Message delivery failed |
| `IOP.Tr.RoutingTableUpdated` | tableId, version, changeCount | Routing table updated |
| `IOP.Tr.CacheHit` | cacheId, key | Translation or route resolved from cache |
| `IOP.Tr.CacheMiss` | cacheId, key | Translation or route not in cache |
| `IOP.Tr.TranslationError` | translatorId, errorCode, message | Translation encountered a runtime error |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No translation rules found for version pair | `IOP_TR_001` | Reject message; suggest available translation paths |
| Type coercion fails (lossy or incompatible) | `IOP_TR_002` | Reject field; use fallback value or skip with warning |
| No route found for contract reference | `IOP_TR_003` | Return routing failure; check routing table or default route |
| Subscription delivery exhausted retries | `IOP_TR_004` | Move to dead-letter queue; emit delivery failure event |
| Translation cache invalidation conflict | `IOP_TR_005` | Invalidate entire cache partition; rebuild on next request |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IOP-TR-001 | Translation is idempotent — applying the same translation twice produces identical output | Algorithmic — translation rules are pure functions; no mutable state in translation pipeline |
| IOP-TR-002 | Routing is deterministic given the same contract ID, payload, and routing table | Algorithmic — route selection uses stable sort by priority, then route ID |
| IOP-TR-003 | Cross-protocol translation preserves semantic equivalence of the original message | Architectural — translation verified by round-trip test after each rule update |
| IOP-TR-004 | Subscription delivery respects the configured delivery guarantee (at-most-once, at-least-once, exactly-once) | Algorithmic — delivery dispatcher enforces retry policy and deduplication logic |
| IOP-TR-005 | Cache invalidation is atomic — no stale routes are served after routing table update | Architectural — cache invalidation completes before routing table update is acknowledged |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Translation Engine owns field mapping; Routing Engine owns message dispatch; Cache Manager owns performance optimization |
| R2 — Dependency Order | Translation depends on Protocol Adapters (format conversion) and Contract Registry (schema lookup); no circular dependencies |
| R3 — DRY | Translation rules are defined once per version pair and reused for all messages sharing that contract pair |
| R9 — Deterministic | Given the same input payload and translation rules, translation produces identical output |
| R10 — Simpler Over Complex | Direct field mapping with implicit type coercion handles most version migration scenarios; custom transformations are opt-in |
| R13 — Design for Failure | Delivery failures trigger retry with backoff; dead-letter queue captures undeliverable messages; cache misses degrade gracefully |
| R14 — Paved Path | Version-to-version translation with direct field mapping and at-least-once delivery covers the majority of integration scenarios |
| R15 — Open/Closed | New translation rules can be added without modifying the translation engine; routing strategies are extensible |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Overview.md | Parent document — IOP architecture, messaging patterns, and component map |
| 001-Protocols.md | Protocol definitions and versioning that translation rules reference |
| 002-Adapters.md | Format converters used during cross-protocol translation |
| Bible/06-Services/ACF/000-Overview.md | ACF transports translated messages to their routed destinations |
| Bible/00-Foundations/009-Versioning.md | Versioning policies that govern contract version translation |
| Physics/009-Interaction.md | Interaction invariants for message translation and routing determinism |
