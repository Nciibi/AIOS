# AIOS Bible — Services
## 001 — Protocols & Contract Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services/Interop |
| Document ID | AIOS-BBL-006-IOP-001 |
| Source Laws | Law 3 — Law of Communication, Law 5 — Law of Identity, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Define supported communication protocols, contract lifecycle management, and protocol negotiation mechanics for the Interoperability Protocol. This document specifies how protocols are registered, versioned, negotiated, and how contracts evolve through their lifecycle stages with immutability guarantees and migration strategies.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Protocol & Contract Layer                    │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │ Protocol Registry│  │   Contract Lifecycle Manager     │  │
│  │  (supported      │  │  (Draft→Published→Dep→Retired)   │  │
│  │   protocols)     │  │                                  │  │
│  └────────┬────────┘  └──────────────┬───────────────────┘  │
│           │                          │                       │
│  ┌────────▼──────────────────────────▼───────────────────┐  │
│  │              Version Negotiator                        │  │
│  │  (compatibility check, highest common version)         │  │
│  └─────────────────────────┬────────────────────────────┘  │
│                            │                                │
│  ┌─────────────────────────▼────────────────────────────┐  │
│  │           Contract Registry (store + serve)            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│                    IOP Protocol Layer                        │
└─────────────────────────────────────────────────────────────┘
```

## Data Model

```typescript
interface ProtocolDef {
  protocolId: string;
  name: 'iop-native' | 'grpc' | 'rest' | 'websocket' | 'mqtt';
  version: ProtocolVersion;
  capabilities: ProtocolCapability[];
  configSchema: Record<string, unknown>;
  isDefault: boolean;
}

interface ProtocolVersion {
  major: number;
  minor: number;
  patch: number;
  label?: string;
}

interface ProtocolCapability {
  capabilityId: string;
  description: string;
  supportedFormats: SerializationFormat[];
  maxPayloadSize: number;
  supportsStreaming: boolean;
  supportsBidirectional: boolean;
}

interface ContractLifecycle {
  contractId: string;
  currentStage: 'draft' | 'published' | 'deprecated' | 'retired';
  stageTimestamps: Record<string, Timestamp>;
  replacementContractId?: string;
  deprecationNoticePeriod: Duration;
  migrationStrategy: ContractMigration;
  allowedTransitions: [string, string][];
}

interface ContractMigration {
  strategyId: string;
  type: 'version-coexistence' | 'direct-replacement' | 'phased-rollout';
  sourceVersion: ProtocolVersion;
  targetVersion: ProtocolVersion;
  coexistencePeriod: Duration;
  fallbackEnabled: boolean;
  migrationDeadline?: Timestamp;
}

interface NegotiationResult {
  contractId: string;
  offeredVersions: ProtocolVersion[];
  selectedVersion: ProtocolVersion;
  selectedProtocol: ProtocolDef;
  compatibilityScore: number;
  status: 'agreed' | 'fallback' | 'rejected';
  fallbackReason?: string;
}

interface CompatibilityResult {
  contractId: string;
  versionA: ProtocolVersion;
  versionB: ProtocolVersion;
  compatible: boolean;
  direction: 'forward' | 'backward' | 'full' | 'none';
  breakingChanges: string[];
  recommendedAction: string;
}
```

## Core Concepts / Operations

### Supported Protocols

| Protocol | Priority | Use Case | Default |
|----------|----------|----------|---------|
| IOP Native | 1 | Agent-to-agent internal communication | Yes |
| gRPC | 2 | High-performance service calls | No |
| REST | 3 | External integration, HTTP APIs | No |
| WebSocket | 4 | Real-time bidirectional streaming | No |
| MQTT | 5 | IoT, lightweight pub-sub | No |

### Protocol Versioning Scheme

Versions follow semantic versioning (MAJOR.MINOR.PATCH). MAJOR version increments indicate breaking changes. MINOR version increments indicate backward-compatible additions. PATCH version increments indicate backward-compatible bug fixes. Protocol capabilities are advertised per version and used during negotiation.

### Contract Lifecycle State Machine

```
        ┌──────────┐
        │  Draft   │
        └────┬─────┘
             │ publish
             ▼
        ┌───────────┐
        │ Published │
        └─────┬─────┘
              │ deprecate
              ▼
        ┌────────────┐
        │ Deprecated │
        └─────┬──────┘
              │ retire (after notice period)
              ▼
        ┌─────────┐
        │ Retired │
        └─────────┘
```

Transition rules:
- Draft → Published: Contract passes validation, all dependencies satisfied, no breaking changes from prior published version.
- Published → Deprecated: Replacement contract published and registered. Existing consumers get minimum notice period (configurable per contract).
- Deprecated → Retired: Notice period elapsed. New lookups return null. Existing cached references eventually fail.
- Draft → Draft: Allowed (immutable within same draft version, new draft version for changes).
- Published → Published: Not allowed — published contracts are immutable. Changes require new version.
- Deprecated → Published: Not allowed — deprecation is terminal. Create new contract version.
- Retired: Terminal state. No transitions out.

### Contract Migration Strategy

Version coexistence is the default strategy: multiple contract versions operate simultaneously during the deprecation notice period. The migration strategy specifies whether the old version is replaced directly, phased out gradually, or coexists indefinitely with a deadline.

### Protocol Capability Negotiation

The negotiation process:
1. Sender announces supported protocols and versions for a contract.
2. Receiver evaluates against its own supported set.
3. Highest mutually-supported version is selected.
4. If no exact match, fallback to lowest common ancestor.
5. If no common version, negotiation fails.

### Backward Compatibility Guarantees

Published contracts guarantee backward compatibility within the same MAJOR version. MINOR and PATCH updates are backward-compatible. MAJOR version bumps require a new contract ID or explicit deprecation path. The compatibility checker evaluates field additions, removals, type changes, and constraint changes against the compatibility contract.

### Contract Immutability Enforcement

Published, Deprecated, and Retired contracts are immutable in the Contract Registry. Any mutation attempt (field modification, deletion, schema change) is rejected at the registry level. Contracts in Draft status may be updated; each update creates a new draft version entry.

## Internal Interfaces

```typescript
interface ProtocolRegistry {
  registerProtocol(protocol: ProtocolDef): Promise<void>;
  unregisterProtocol(protocolId: string): Promise<void>;
  lookupProtocol(protocolId: string): Promise<ProtocolDef>;
  listSupportedProtocols(): Promise<ProtocolDef[]>;
  getDefaultProtocol(): Promise<ProtocolDef>;
}

interface ContractLifecycleManager {
  transition(contractId: string, targetStage: string): Promise<void>;
  getLifecycle(contractId: string): Promise<ContractLifecycle>;
  enforceTransitionRules(contractId: string, from: string, to: string): Promise<boolean>;
  scheduleRetirement(contractId: string, noticePeriod: Duration): Promise<void>;
}

interface VersionNegotiator {
  negotiate(contractId: string, offered: ProtocolVersion[]): Promise<NegotiationResult>;
  checkCompatibility(contractId: string, version: ProtocolVersion): Promise<CompatibilityResult>;
  findHighestCommon(versionsA: ProtocolVersion[], versionsB: ProtocolVersion[]): Promise<ProtocolVersion | null>;
}

interface ContractRegistry {
  store(contract: MessageContract): Promise<void>;
  retrieve(contractId: string, version?: ProtocolVersion): Promise<MessageContract>;
  transitionLifecycle(contractId: string, target: string): Promise<void>;
  enforceImmutability(contractId: string): Promise<boolean>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `IOP.Proto.ProtocolRegistered` | protocolId, name, version | New protocol registered in the registry |
| `IOP.Proto.ContractPublished` | contractId, version | Contract transitioned to Published stage |
| `IOP.Proto.ContractDeprecated` | contractId, version, replacementId, noticePeriod | Contract marked for deprecation |
| `IOP.Proto.ContractRetired` | contractId, version | Contract removed from active registry |
| `IOP.Proto.ContractMigrated` | contractId, sourceVersion, targetVersion, strategy | Contract migration completed |
| `IOP.Proto.VersionNegotiated` | contractId, entityA, entityB, selectedVersion | Version agreed between peers |
| `IOP.Proto.VersionMismatch` | contractId, entityA, entityB, offeredA, offeredB | No common version found |
| `IOP.Proto.CompatibilityChecked` | contractId, versionA, versionB, compatible | Compatibility evaluation completed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Protocol not registered | `IOP_PROTO_001` | Reject operation; list available protocols |
| Invalid lifecycle transition | `IOP_PROTO_002` | Reject transition; return allowed transitions |
| No compatible version found | `IOP_PROTO_003` | Negotiation fails; return supported version ranges |
| Contract mutation after publish | `IOP_PROTO_004` | Reject mutation; contracts are immutable |
| Migration deadline exceeded | `IOP_PROTO_005` | Force retirement; notify all consumers |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IOP-PROTO-001 | Published contracts are immutable — no field modification, no deletion | Architectural — Contract Registry rejects mutation requests for published, deprecated, or retired contracts |
| IOP-PROTO-002 | Version negotiation always selects the highest mutually-supported version | Algorithmic — negotiator sorts versions descending, selects first match across both sets |
| IOP-PROTO-003 | Deprecated contracts retain full functionality for existing consumers | Algorithmic — deprecation only adds metadata; schema, endpoints, and protocol bindings unchanged |
| IOP-PROTO-004 | Lifecycle transitions follow the defined state machine — no skipped stages | Architectural — life cycle manager validates transition rules before applying any change |
| IOP-PROTO-005 | Contract migration preserves a coexistence window before forced retirement | Configurable — migration strategy enforces minimum notice period before retirement is permitted |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Protocol management is owned by IOP Protocol Layer; transport is owned by ACF; contract storage is owned by Contract Registry |
| R2 — Dependency Order | Protocol layer depends on Contract Registry and Version Negotiator; no circular dependencies |
| R3 — DRY | Protocol definitions are registered once and referenced by ID; contracts reference protocols, not duplicate |
| R9 — Deterministic | Given same offered versions, negotiation produces identical selected version |
| R10 — Simpler Over Complex | Default to IOP Native protocol; gRPC and MQTT are opt-in for specialized use cases |
| R13 — Design for Failure | Version mismatch falls back with error details; migration coexistence prevents abrupt breaking changes |
| R14 — Paved Path | Standard contract lifecycle (Draft → Published → Deprecated → Retired) with default IOP Native protocol covers most scenarios |
| R15 — Open/Closed | New protocols can be registered without modifying Protocol Registry internals; lifecycle stages are extensible |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Overview.md | Parent document — IOP architecture, core concepts, and component map |
| 002-Adapters.md | Protocol Adapters implement serialization for registered protocols |
| 003-Translation.md | Message translation routes messages based on contract references |
| Bible/00-Foundations/009-Versioning.md | Versioning policies apply to IOP protocol and contract versioning |
| Bible/06-Services/ACF/000-Overview.md | ACF is the transport layer that carries IOP protocol messages |
| Physics/009-Interaction.md | Interaction invariants for message structure and protocol negotiation |
