# AIOS Bible — Services
## ACF 007 — Distributed

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-007 |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Multi-instance ACF, partition tolerance, and eventual consistency across distributed AIOS instances. ACF spans AIOS instances through federation — cross-instance ACF bridges authenticated, routed, and bandwidth-managed connections between independent AIOS deployments.

## Federation Model

Each AIOS instance runs its own ACF cluster. Instances connect through ACF bridges:

```
┌─────────────────┐         ┌─────────────────┐
│  AIOS Instance A │         │  AIOS Instance B │
│  ┌───────────┐   │  Bridge  │  ┌───────────┐   │
│  │ ACF A     │───╪══════════╪───│ ACF B     │   │
│  └───────────┘   │         │  └───────────┘   │
│  ┌───────────┐   │         │  ┌───────────┐   │
│  │ Services  │   │         │  │ Services  │   │
│  └───────────┘   │         │  └───────────┘   │
└─────────────────┘         └─────────────────┘
```

## Cross-Instance Message Format

Cross-instance messages extend the standard ACF message format:

```
CrossInstanceEnvelope {
  // Standard envelope fields
  version: int,
  message_id: UUIDv7,
  sender: Address,
  target: Address,
  timestamp: HLC,
  auth_token: string,
  
  // Cross-instance fields
  origin_instance: string,     // originating AIOS instance ID
  hop_count: int,              // number of bridges traversed (max 5)
  trace_id: UUID,              // tracing identifier
  instance_path: string[],     // list of instances traversed
  bridge_credentials: string   // signed bridge authentication
}
```

## Partition Tolerance

In a network partition, each partition's ACF continues operating independently:

| Partition State | ACF A (Instance 1) | ACF B (Instance 2) |
|----------------|-------------------|-------------------|
| **Connected** | Full operation | Full operation |
| **Partitioned** | Local operation only | Local operation only |
| **Reconnecting** | Queue cross-instance messages | Queue cross-instance messages |
| **Reconnected** | Replay queued messages | Replay queued messages |

### Partition Recovery

When a partition heals:

1. **Clock sync**: HLC clocks are resynchronized across instances
2. **Queue drain**: Queued cross-instance messages are replayed
3. **Routing sync**: Routing tables are synchronized
4. **Conflict resolution**: Conflicting state is resolved by HLC timestamp
5. **Events produced**: Partition recovery Events are recorded

## Federation Requirements

Cross-instance ACF requires:

| Requirement | Specification |
|-------------|---------------|
| **Authentication** | Instance identity verified via X.509 certificates |
| **Authorization** | Cross-instance routing table agreed by both instances |
| **Bandwidth** | Allocated bandwidth per bridge connection |
| **Latency budget** | Maximum acceptable cross-instance latency |
| **Message filtering** | Configurable filter for cross-instance messages |

## Federation Operations

```
connectInstance(instance_url, credentials) → bridge_id
disconnectInstance(bridge_id) → void
syncRoutingTable(bridge_id) → void
getInstanceStatus(instance_id) → InstanceStatus
listConnectedInstances() → InstanceInfo[]
updateBandwidth(bridge_id, bandwidth) → void
```

## Bridge Lifecycle

```
Configured → Connecting → Authenticating → Active → Partitions → Reconnecting → Disconnected → Archived
```

| State | Description |
|-------|-------------|
| **Configured** | Bridge configuration defined |
| **Connecting** | TCP/TLS handshake in progress |
| **Authenticating** | Instance identity verified |
| **Active** | Messages flowing between instances |
| **Partitioned** | Network failure, queueing messages |
| **Reconnecting** | Attempting to re-establish connection |
| **Disconnected** | Bridge torn down intentionally |
| **Archived** | Bridge configuration preserved for audit |

## Routing Federation

Across instances, routing tables are partially synchronized:

- **Local routes**: Only visible within the instance
- **Exported routes**: Explicitly shared with other instances
- **Imported routes**: Routes received from other instances

Route export/import is controlled by each instance's Security Council. An instance may choose to export only specific services or entity types.

## ACF Distributed Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.InstanceConnected` | An ACF bridge is established | bridge_id, instance_id, remote_endpoint |
| `ACF.InstanceDisconnected` | A bridge is torn down | bridge_id, instance_id, reason |
| `ACF.InstancePartitioned` | Network partition detected | bridge_id, instance_id, last_contact |
| `ACF.InstanceReconnected` | Network partition healed | bridge_id, instance_id, queued_message_count |
| `ACF.RoutingTableSynced` | Routing tables are synchronized | bridge_id, routes_exported, routes_imported |
| `ACF.CrossInstanceMessageSent` | A message crosses instances | message_id, source_instance, target_instance, hop_count |
| `ACF.HopLimitExceeded` | Message exceeds max hop count | message_id, hop_count, max_hops |
| `ACF.BandwidthExceeded` | Cross-instance bandwidth limit hit | bridge_id, allocated, actual, throttle_applied |

## Cross-Cutting Concerns

### Security

Cross-instance communication requires mutual authentication via X.509 certificates. Bridge credentials are signed. All cross-instance traffic is encrypted (mTLS). Instance identity is verified before routing table sync.

### Evidence

Every bridge lifecycle transition produces an Event. Cross-instance messages produce Events on both sides. Partition events are critical audit Events.

### Lifecycle

Bridges follow the defined lifecycle. Cross-instance routing tables follow: Synced → Diverged → Resynced. Federation agreements are versioned.

### Capability Bounds

Distributed ACF only manages cross-instance communication. It does not enforce consistency across instances (eventual consistency), does not manage instance resources, and does not coordinate instance lifecycle.

### Communication

Distributed ACF communicates between instances through encrypted bridges. Bridge management uses ACF messages within each instance. Cross-instance messages use the extended envelope format.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Distributed ACF does one thing: cross-instance messaging |
| R2 — Dependency Order | Depends on ACF Core; no upward deps |
| R3 — DRY | Bridge configurations are the single source for federation |
| R4 — Builder Pattern | Bridges are built by BridgeBuilders with security validation |
| R5 — Liskov | All transport backends implement the same Bridge interface |
| R6 — DI over Singletons | Distributed ACF receives ACF Core as injected dependency |
| R7 — Tests Exist | Every partition scenario and reconnection flow has tests |
| R8 — Tests Fast | Bridge lifecycle tests complete in <100ms |
| R9 — Deterministic | Same messages in same order delivered same way on reconnection |
| R10 — Simpler Over Complex | Bridges are point-to-point; no mesh routing |
| R11 — Refactor Over Rewrite | Federation protocols evolve via versioned upgrades |
| R12 — Embrace Errors | Every bridge failure has a unique error code |
| R13 — Design for Failure | Partitions are expected; queues preserve messages |
| R14 — Paved Path | Distributed ACF is the only path for cross-instance messaging |
| R15 — Open/Closed | New federation protocols extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-Architecture.md | ACF architecture — distributed components |
| 003-Routing.md | Routing table federation |
| 006-Reliability.md | Cross-instance delivery guarantees |
| 06-Services/Federation/000-Overview.md | Federation protocols |
| 04-Execution/Security/IDS/004-Federation.md | Identity federation across instances |
| Physics/009-Interaction.md | Interaction model across instances |
