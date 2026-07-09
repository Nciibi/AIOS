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
┌────────────────────────┐         ┌────────────────────────┐
│   AIOS Instance A      │         │   AIOS Instance B      │
│                        │         │                        │
│  ┌──────────────────┐  │ Bridge  │  ┌──────────────────┐  │
│  │   Services       │  │◄═══════►│  │   Services       │  │
│  │   ┌──────────┐   │  │  mTLS  │  │   ┌──────────┐   │  │
│  │   │ ACF A    │───╪══╪════════╪══╪───│ ACF B    │   │  │
│  │   └──────────┘   │  │         │  │   └──────────┘   │  │
│  │   ┌──────────┐   │  │         │  │   ┌──────────┐   │  │
│  │   │ PSAP     │   │  │         │  │   │ PSAP     │   │  │
│  │   └──────────┘   │  │         │  │   └──────────┘   │  │
│  └──────────────────┘  │         │  └──────────────────┘  │
└────────────────────────┘         └────────────────────────┘
```

## Cross-Instance Message Format

Cross-instance messages extend the standard ACF message format:

```
CrossInstanceEnvelope {
  // Standard envelope fields (inherited from ACF Message)
  version: int,
  message_id: UUIDv7,
  sender: Address,
  target: Address,
  timestamp: HLC,
  auth_token: string,
  
  // Cross-instance fields (added by Distributed Coordinator)
  origin_instance: string,       // originating AIOS instance ID
  hop_count: int,                // bridges traversed (max 5)
  trace_id: UUID,                // distributed tracing ID
  instance_path: string[],       // list of instances traversed
  bridge_credentials: string,    // signed bridge authentication
  bandwidth_budget: int          // allocated bandwidth for this message
}
```

### Hop Limit

Maximum hop count: 5. When hop_count reaches 5, the message is rejected with `ACF.HopLimitExceeded`. This prevents infinite loops in federated message routing.

## Partition Tolerance

In a network partition, each partition's ACF continues operating independently:

| Phase | Instance A | Instance B | Message Flow |
|-------|-----------|-----------|--------------|
| **Connected** | Full operation | Full operation | Bidirectional |
| **Partitioned** | Local operation | Local operation | Queued locally |
| **Reconnecting** | Queue cross-instance | Queue cross-instance | Buffered |
| **Reconnected** | Replay queued messages | Replay queued messages | Drain queues |

### Partition Recovery

When a partition heals:

```
1. Clock sync: HLC clocks resynchronized via NTS (Network Time Service)
2. Reconnection: mTLS handshake re-established
3. Queue drain: Queued messages replayed in order (per-instance FIFO)
4. Routing sync: Export/import routing tables
5. Conflict resolution: Conflicting state resolved by HLC timestamp
6. Events produced: ACF.InstanceReconnected Event with stats
7. Normal operation resumes
```

## Federation Requirements

| Requirement | Specification | Enforcement |
|-------------|---------------|-------------|
| Authentication | X.509 certificates | mTLS handshake |
| Authorization | Agreed routing table | Bilateral agreement |
| Bandwidth | Allocated per bridge | Token bucket shaping |
| Latency budget | Configurable (default 500ms) | Message TTL |
| Message filtering | Configurable filter | Route-level filter |

### Bridge Authentication

Bridge authentication uses mutual TLS:

1. Each instance presents its X.509 certificate during TLS handshake
2. Certificate is verified against the federation CA
3. Instance identity extracted from certificate CN/SAN
4. Instance checked against federation allow-list
5. If authorized, bridge connection established

## Routing Federation

Across instances, routing tables are partially synchronized:

| Route Type | Visibility | Synchronization |
|------------|------------|-----------------|
| **Local routes** | Instance only | Not shared |
| **Exported routes** | Shared with federation | Pushed to connected instances |
| **Imported routes** | Received from federation | Merged into routing table |

### Route Export/Import

```
ExportedRoute {
  service_name: string,
  target_pattern: string,
  capabilities: string[],
  endpoint: Address,
  version: string,
  export_policy: ExportPolicy
}
```

Each instance's Security Council controls which routes are exported and which imports are accepted.

## Federation Operations

```
connectInstance(instance_url, credentials, config) → bridge_id
disconnectInstance(bridge_id) → void
syncRoutingTable(bridge_id) → SyncResult
getInstanceStatus(instance_id) → InstanceStatus
listConnectedInstances() → InstanceInfo[]
updateBandwidth(bridge_id, bandwidth_bps) → void
updateExportPolicy(bridge_id, policy) → void
```

### Bridge Lifecycle

```
Configured → Connecting → Authenticating → Active → 
Partitioned → Reconnecting → Disconnected → Archived
```

| State | Description | Message Flow |
|-------|-------------|--------------|
| **Configured** | Bridge configuration defined | None |
| **Connecting** | TCP/TLS handshake in progress | None |
| **Authenticating** | Instance identity being verified | None |
| **Active** | Messages flowing between instances | Bidirectional |
| **Partitioned** | Network failure detected | Queued |
| **Reconnecting** | Attempting reconnection | Queued |
| **Disconnected** | Bridge intentionally torn down | Blocked |
| **Archived** | Bridge decommissioned | None |

## Performance Characteristics

| Metric | Intra-Instance | Cross-Instance |
|--------|---------------|----------------|
| P50 latency | <10ms | <100ms (same region) |
| P99 latency | <100ms | <500ms (same region) |
| Throughput | >100K msg/s | >10K msg/s per bridge |
| Max bridges per instance | N/A | 100 |
| Max instances in federation | N/A | 50 |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| ACF-DIST-001 | BridgeNotFound | No bridge with the given ID |
| ACF-DIST-002 | AuthenticationFailed | Instance certificate verification failed |
| ACF-DIST-003 | AuthorizationDenied | Instance not in federation allow-list |
| ACF-DIST-004 | HopLimitExceeded | Message exceeded maximum hop count |
| ACF-DIST-005 | BandwidthExceeded | Bridge bandwidth limit reached |
| ACF-DIST-006 | InstanceUnreachable | Remote instance not responding |
| ACF-DIST-007 | RoutingSyncFailed | Could not synchronize routing tables |
| ACF-DIST-008 | ProtocolMismatch | Instances running incompatible ACF versions |

## ACF Distributed Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.InstanceConnected` | ACF bridge established | bridge_id, instance_id, remote_endpoint, protocol_version |
| `ACF.InstanceDisconnected` | Bridge torn down | bridge_id, instance_id, reason, uptime_seconds |
| `ACF.InstancePartitioned` | Network partition detected | bridge_id, instance_id, last_contact, queued_messages |
| `ACF.InstanceReconnected` | Partition healed | bridge_id, instance_id, queued_message_count, drain_duration |
| `ACF.RoutingTableSynced` | Routing tables synchronized | bridge_id, routes_exported, routes_imported, sync_duration |
| `ACF.CrossInstanceMessageSent` | Message crosses instance boundary | message_id, source_instance, target_instance, hop_count |
| `ACF.CrossInstanceMessageReceived` | Message received from remote | message_id, source_instance, local_target, delivery_latency |
| `ACF.HopLimitExceeded` | Message exceeds max hops | message_id, hop_count, max_hops, last_instance |
| `ACF.BandwidthExceeded` | Bandwidth limit hit | bridge_id, allocated_bps, actual_bps, throttle_applied |

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
