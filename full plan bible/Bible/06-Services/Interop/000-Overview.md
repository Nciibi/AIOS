# AIOS Bible — Services
## 000 — Interoperability Protocol (IOP)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services/Interop |
| Document ID | AIOS-BBL-006-IOP-000 |
| Source Laws | Law 3 — Communication, Law 5 — Identity, Law 4 — Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Interoperability Protocol enables standardized, discoverable, versioned communication between agents, services, and external systems. Built on top of ACF (Law 3), IOP provides message contract management, protocol negotiation, and service discovery — ensuring that any entity can communicate with any other entity through a well-defined, versioned, and validated interface.

IOP does not replace ACF. ACF is the universal communication fabric — it handles routing, identity verification, and transport. IOP is the semantic layer above ACF — it defines what messages mean, what format they follow, how contracts evolve, and how entities discover each other. Every message through ACF may carry an IOP contract reference; every IOP message is transported through ACF.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Entity A                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────────┐ │
│  │ Application│  │ IOP Client │  │ Contract       │ │
│  │ Logic      │◄─┤ Library    │◄─┤ Resolver (cache)│ │
│  └────────────┘  └──────┬─────┘  └────────────────┘ │
└─────────────────────────┼────────────────────────────┘
                          │
                    ACF Message Bus
                          │
┌─────────────────────────┼────────────────────────────┐
│                         ▼                            │
│              ┌─────────────────────┐                 │
│              │   Contract Registry │                 │
│              │  (store + serve)    │                 │
│              └──────────┬──────────┘                 │
│                         │                            │
│              ┌──────────▼──────────┐                 │
│              │    Protocol Adapter │                 │
│              │  (serialize/deser)  │                 │
│              └──────────┬──────────┘                 │
│                         │                            │
│              ┌──────────▼──────────┐                 │
│              │   Discovery Service │                 │
│              │  (service registry) │                 │
│              └─────────────────────┘                 │
│                                                      │
│                  IOP Services                        │
└──────────────────────────────────────────────────────┘
```

## Core Concepts

### 1. Message Contract

A typed, versioned schema defining the structure and semantics of messages exchanged between entities. Each contract specifies the message fields (name, type, constraints, documentation), the supported protocol version, and the endpoint definitions (operations the contract enables). Contracts are identified by globally unique Contract IDs.

### 2. Contract Lifecycle

Contracts progress through a defined lifecycle: **Draft → Published → Deprecated → Retired**.

| Stage | Description | Consumers |
|-------|-------------|-----------|
| Draft | Under development, may change without notice | Development only |
| Published | Stable, versioned, ready for production use | All entities |
| Deprecated | Still functional but marked for replacement | Existing consumers continue working |
| Retired | Removed from registry; new lookups return null | None (existing cached references eventually fail) |

The lifecycle ensures backward compatibility: Published contracts are immutable (IOP-002), Deprecated contracts retain full functionality (IOP-003), and Retirement includes a mandatory notice period.

### 3. Contract Discovery

Entities discover compatible contracts by querying the Contract Registry. Discovery supports lookup by Contract ID (exact match), by service type + version range (find all contracts matching criteria), and by capability (find contracts that enable a specific function). Discovery responses include contract metadata, current lifecycle stage, and endpoint information.

### 4. Serialization

IOP supports Protocol Buffers (primary, for internal high-performance communication) and JSON (secondary, for external integration and debugging). The Protocol Adapter handles serialization and deserialization, validates payloads against the contract schema, and reports validation failures as structured errors.

### 5. Message Routing

Routing is handled by ACF at the transport layer (Law 3). IOP augments routing with contract-level dispatch: when a message arrives with a contract reference, ACF consults IOP to validate the contract, resolve the target endpoint, and confirm version compatibility before delivery. Topic-based routing (publish-subscribe) is supported via subscriptions linked to contract identifiers.

### 6. Version Negotiation

When two entities need to communicate, they negotiate the highest mutually-supported contract version. The negotiation process: sender announces its supported versions → receiver selects the highest mutually-supported version → both parties confirm. Version negotiation is backward-compatible — a newer sender can communicate with an older receiver as long as they share at least one common version.

### 7. Cross-Agent Messaging

IOP supports three messaging patterns:
- **Point-to-Point**: Direct message from one agent to another, routed by agent identity.
- **Broadcast**: Message sent to all agents subscribed to a topic/contract combination.
- **Request-Reply**: A request message expects a correlated reply; IOP tracks the correlation for the caller.

### 8. Contract Dependencies

Contracts may reference other contracts as dependencies (e.g., a Task contract depends on the Identity contract for sender identification). The Contract Registry validates that all dependency contracts exist and are at compatible versions before a contract can be Published.

## Data Model

```typescript
interface MessageContract {
  contractId: string;
  name: string;
  description: string;
  version: Version;
  lifecycle: 'draft' | 'published' | 'deprecated' | 'retired';
  fields: Field[];
  endpoints: EndpointDef[];
  dependencies: ContractDependency[];
  serializationFormat: 'protobuf' | 'json';
  schema: string;  // protobuf .proto content or JSON Schema
  publishedAt: Timestamp;
  deprecatedAt: Timestamp | null;
  retiredAt: Timestamp | null;
}

interface Field {
  name: string;
  type: string;
  required: boolean;
  description: string;
  constraints: Constraint[];
  defaultValue?: unknown;
}

interface EndpointDef {
  name: string;
  operation: 'rpc' | 'event' | 'query';
  requestContract: string;  // contract ID
  responseContract?: string;
  description: string;
}

interface ContractDependency {
  contractId: string;
  minVersion: Version;
  maxVersion: Version;
}

interface ServiceEndpoint {
  endpointId: string;
  entityId: string;
  contracts: ContractBinding[];
  capabilities: string[];
  status: 'active' | 'draining' | 'offline';
}

interface Subscription {
  subscriptionId: string;
  entityId: string;
  topic: string;
  contractId: string;
  filter?: FilterExpression;
  createdAt: Timestamp;
}

interface VersionNegotiation {
  contractId: string;
  offeredVersions: Version[];
  selectedVersion: Version;
  status: 'pending' | 'agreed' | 'rejected';
}
```

## Interfaces

### IOP API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `registerContract(contract)` | Entity | Publish a new contract (Draft or Published) |
| `resolveContract(contractId, version)` | Any | Retrieve a contract by ID and version |
| `discoverContracts(criteria)` | Any | Find contracts matching service type, capability, or version |
| `sendMessage(targetId, contractId, payload)` | Any | Send a point-to-point message |
| `publish(topic, contractId, payload)` | Any | Broadcast a message to subscribers |
| `subscribe(topic, contractId, handler)` | Any | Subscribe to a topic/contract combination |
| `unsubscribe(subscriptionId)` | Any | Remove a subscription |
| `requestReply(targetId, contractId, payload)` | Any | Send a request expecting a correlated reply |
| `replyTo(correlationId, contractId, payload)` | Any | Reply to a prior request |
| `negotiateVersion(contractId, supportedVersions)` | Any | Negotiate highest compatible version |
| `registerEndpoint(endpoint)` | Entity | Register a service endpoint |
| `discoverServices(criteria)` | Any | Find service endpoints matching criteria |

### Internal Interfaces

```typescript
interface ContractRegistry {
  store(contract: MessageContract): Promise<void>;
  retrieve(contractId: string, version?: Version): Promise<MessageContract>;
  search(criteria: ContractCriteria): Promise<MessageContract[]>;
  transitionLifecycle(contractId: string, target: LifecycleStage): Promise<void>;
}

interface ProtocolAdapter {
  serialize<T>(payload: T, contract: MessageContract): Buffer;
  deserialize<T>(data: Buffer, contract: MessageContract): T;
  validate(payload: unknown, contract: MessageContract): ValidationResult;
}

interface DiscoveryService {
  register(endpoint: ServiceEndpoint): Promise<void>;
  unregister(endpointId: string): Promise<void>;
  find(criteria: ServiceCriteria): Promise<ServiceEndpoint[]>;
  heartbeat(endpointId: string): Promise<void>;
}

interface VersionNegotiator {
  negotiate(contractId: string, offered: Version[]): Promise<VersionNegotiation>;
  checkCompatibility(contractId: string, version: Version): Promise<CompatibilityResult>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Contract Registry | Stores, versions, and serves message contracts; manages lifecycle transitions |
| Protocol Adapter | Handles serialization/deserialization; validates payloads against contract schemas |
| Discovery Service | Maintains service endpoint registry; handles heartbeat and health checks |
| Message Router | Routes messages based on contract references; resolves endpoints via Discovery Service |
| Version Negotiator | Manages version compatibility checks; resolves highest mutually-supported version |
| Subscription Manager | Manages topic subscriptions; delivers broadcast messages to subscribers |

## Data Flow

```
Entity A wants to communicate with Entity B
        │
        ▼
Entity A resolves contract via resolveContract()
        │
        ▼
Entity A negotiates version with Entity B via negotiateVersion()
        │
        ▼
Entity A serializes payload using Protocol Adapter (contract schema)
        │
        ▼
ACF transports message to Entity B (Law 3)
        │
        ▼
Entity B receives message; Protocol Adapter validates and deserializes
        │
        ▼
Entity B processes message; sends reply (if request-reply pattern)
        │
        ▼
Both sides emit evidence records (Law 4)
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `IOP.ContractRegistered` | contractId, version, lifecycle | New contract registered |
| `IOP.ContractPublished` | contractId, version | Contract transitioned to Published |
| `IOP.ContractDeprecated` | contractId, version, replacementId | Contract marked for deprecation |
| `IOP.ContractRetired` | contractId, version | Contract removed from registry |
| `IOP.MessageSent` | messageId, contractId, targetId | Message dispatched to target |
| `IOP.MessageReceived` | messageId, contractId, sourceId | Message delivered to recipient |
| `IOP.MessageValidationFailed` | messageId, contractId, errors | Payload failed schema validation |
| `IOP.SubscriptionCreated` | subscriptionId, topic, entityId | New topic subscription |
| `IOP.SubscriptionRemoved` | subscriptionId, topic | Subscription removed |
| `IOP.VersionNegotiated` | contractId, entityA, entityB, selectedVersion | Version agreed between peers |
| `IOP.EndpointRegistered` | endpointId, entityId | Service endpoint registered |
| `IOP.EndpointDraining` | endpointId | Service preparing for shutdown |
| `IOP.EndpointRemoved` | endpointId | Service endpoint unregistered |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Requested contract not found | `IOP_CONTRACT_NOT_FOUND` | Return null; no side effects |
| Payload does not match contract schema | `IOP_SCHEMA_VALIDATION_FAILED` | Reject message; return validation errors |
| No compatible version between sender and receiver | `IOP_VERSION_MISMATCH` | Negotiation fails; fall back to lowest common ancestor or report error |
| Target entity unreachable or unavailable | `IOP_ROUTING_FAILED` | Return delivery failure; no retry (ACF-level retry may apply) |
| No matching service found for criteria | `IOP_DISCOVERY_FAILED` | Return empty result set |
| Duplicate subscription for same topic/contract | `IOP_SUBSCRIPTION_CONFLICT` | Reject new subscription; existing subscription remains |
| Payload exceeds maximum message size | `IOP_PAYLOAD_TOO_LARGE` | Reject; sender must split or compress payload |
| Contract dependency missing or incompatible | `IOP_DEPENDENCY_MISSING` | Reject contract registration; list missing dependencies |
| Endpoint registration with duplicate identity | `IOP_ENDPOINT_CONFLICT` | Reject; entity already has active endpoint |
| Contract mutation after publication attempted | `IOP_CONTRACT_IMMUTABLE` | Reject; published contracts cannot be modified (IOP-002) |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IOP-001 | Every message references a valid published contract (Law 3) | Architectural — IOP Contract Registry validates contract ID before message dispatch |
| IOP-002 | Published contracts are immutable — no field modification, no deletion | Architectural — Contract Registry rejects mutation requests |
| IOP-003 | A deprecated contract retains full functionality for existing consumers | Algorithmic — Deprecation only adds metadata; schema and endpoints unchanged |
| IOP-004 | Message routing is deterministic given the same contract, payload, and target | Algorithmic — subscription matching produces stable ordering |
| IOP-005 | Every message transmission produces an evidence record (Law 4) | Architectural — ACF emits delivery event on every message |
| IOP-006 | Contract IDs are globally unique across the platform | Architectural — Contract Registry enforces unique constraint |
| IOP-007 | Version negotiation always prefers the highest mutually-supported version | Algorithmic — negotiation sorts versions descending, selects first match |
| IOP-008 | Subscription filters are evaluated on the recipient side, never the sender | Architectural — sender broadcasts to all subscribers; recipient-side filtering |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | IOP owns the semantic communication layer; ACF owns transport; Security Council owns message verification |
| R2 — Dependency Order | IOP depends on ACF (transport), IRS (identity), Security Council (verification); no circular dependencies |
| R3 — DRY | Message schemas are defined once in contracts; entities reference, not duplicate |
| R4 — Builder Pattern | Contract construction uses builder for complex field and dependency validation |
| R9 — Deterministic | Given the same contract and payload, serialization produces identical output |
| R10 — Simpler Over Complex | Default JSON serialization works for most cases; Protobuf is opt-in for performance-critical paths |
| R13 — Design for Failure | Schema validation catches malformed messages before routing; version negotiation degrades gracefully |
| R14 — Paved Path | Standard request-reply with JSON and a single published contract covers most integration scenarios |
| R15 — Open/Closed | New serialization formats can be registered via Protocol Adapter extension; contract lifecycle stages are extensible |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/06-Services/ACF/000-Overview.md | ACF is the transport layer that IOP builds upon |
| Bible/02-Core/Brain/Conversation/000-Overview.md | Conversation OS uses IOP for inter-agent dialogue contracts |
| Bible/02-Core/Brain/Tools/000-Overview.md | Tool System uses IOP for tool invocation contracts and discovery |
| Bible/02-Core/AGS/000-Overview.md | AGS genomes declare which IOP contracts agents support |
| Bible/04-Execution/Security/000-Overview.md | Security Council verifies contract authenticity and message integrity |
| Bible/04-Execution/Security/IDS/001-Registry.md | IDS provides identity resolution for message routing |
| Bible/00-Foundations/009-Versioning.md | Versioning policies apply to IOP contract lifecycle |
| Bible/05-Platform/004-EVS.md | EVS stores message evidence records |
| Bible/05-Platform/Observability/000-AOP.md | AOP monitors message throughput and contract health |
| Physics/009-Interaction.md | Interaction invariants — message structure, routing, contracts |
| Physics/008-Security.md | Security invariants — message integrity, authentication |
