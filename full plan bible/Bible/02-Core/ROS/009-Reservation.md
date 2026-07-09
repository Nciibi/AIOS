# AIOS Bible — Core
## 009 — Resource Reservation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-009 |
| Source Laws | Law 12 — Law of Bounded Capability, Law 8 — Law of Proportionality |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Resource reservation bridges the verification pipeline (Stage 7 — Execution Authorization) and actual resource allocation. When a capability passes all 6 prior verification stages, Stage 7 instructs ROS to reserve the required resources. The reservation is time-bound: if the execution does not start within the TTL, the reservation expires and resources return to the pool. This prevents deadlocks and ensures liveness per ROS-005.

## Reservation Flow

```
Stage 7 (Execution Authorization)
    │
    ▼
ROS reserves resources ──→ If insufficient: DENY execution
    │
    ▼
Execution token issued (with reservation_id)
    │
    ▼
    ├── Entity starts execution ──→ Reservation consumed
    │                                  │
    │                                  ▼
    │                              Resources allocated
    │                                  │
    │                                  ▼
    │                              Execution completes
    │                                  │
    │                                  ▼
    │                              Resources released
    │
    ├── TTL expires ──→ Reservation expired
    │                      │
    │                      ▼
    │                  Resources returned to pool
    │                  Execution token invalidated
    │
    └── Entity releases ──→ Reservation released
                               │
                               ▼
                           Resources returned to pool
```

## Reservation Structure

```
Reservation {
    reservation_id: UUID
    entity_id: UUID
    capability_id: UUID
    execution_token_id: UUID          // Linked execution token
    resources: Map<ResourceType, Quantity>
    provider_id: UUID (optional)      // Pre-selected provider
    status: ReservationStatus
    created_at: Timestamp
    expires_at: Timestamp
    consumed_at: Timestamp (optional)
    released_at: Timestamp (optional)
}
```

## Reservation States

```
                    ┌──────────┐
                    │  Pending │
                    └────┬─────┘
                         │ Resources confirmed available
                         ▼
                    ┌──────────┐
           ┌────────│  Active  │────────┐
           │        └──────────┘        │
           │              │              │
           ▼              ▼              ▼
    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │ Consumed │   │ Expired  │   │ Released │
    └──────────┘   └──────────┘   └──────────┘
```

| State | Description | Transition |
|-------|-------------|------------|
| Pending | Reservation request received, resources being confirmed | → Active (resources confirmed) |
| Active | Resources are reserved and held for the entity | → Consumed (execution starts), → Expired (TTL reached), → Released (entity cancels) |
| Consumed | Entity has started execution and resources are allocated | Terminal |
| Expired | TTL reached without consumption | Terminal |
| Released | Entity explicitly released the reservation | Terminal |

## Reservation Operations

### createReservation

Creates a new resource reservation for execution authorization.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | UUID | Entity requesting reservation |
| `capability_id` | UUID | Capability to execute |
| `resources` | Map<ResourceType, Quantity> | Required resources |
| `ttl` | Duration | Time-to-live (default: matches execution token TTL) |
| `execution_token_id` | UUID | Associated execution token |

**Process**:
1. Verify entity identity and capability authorization
2. Check budget (005-Budget) — fail if insufficient
3. Check quota (006-Quota) — fail if hard quota exceeded
4. Query Registry (002-Registry) for provider availability
5. Tentatively reserve resources (mark as pending allocation)
6. Create reservation record
7. Link to execution token
8. Return reservation_id with expiry

**Event produced**: `ReservationCreated { reservation_id, entity_id, capability_id, resources, ttl, expires_at, timestamp }`

### consumeReservation

Marks a reservation as consumed when execution starts.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reservation_id` | UUID | Reservation to consume |
| `execution_token_id` | UUID | Verification token |

**Process**:
1. Validate reservation is in Active state
2. Validate execution_token matches
3. Convert reservation to actual allocation via Allocator (003-Allocator)
4. Mark reservation as Consumed
5. Update budget usage

**Event produced**: `ReservationConsumed { reservation_id, entity_id, allocation_id, timestamp }`

### releaseReservation

Releases a reservation without consuming it.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reservation_id` | UUID | Reservation to release |
| `reason` | Enum | voluntary, execution_cancelled, policy_change |

**Event produced**: `ReservationReleased { reservation_id, entity_id, reason, timestamp }`

### expireReservation

Automatically called when reservation TTL expires.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reservation_id` | UUID | Expired reservation |

**Event produced**: `ReservationExpired { reservation_id, entity_id, timestamp }`

## Deadlock Prevention

Reservations have an inherent deadlock prevention mechanism:

| Mechanism | Description |
|-----------|-------------|
| Time-bound TTL | Every reservation has an expiry. No resource is held indefinitely. |
| Automatic expiry | The Reservation Manager periodically scans for expired reservations and releases them. |
| Scan interval | Every 30 seconds |
| Execution token coupling | If the execution token expires before consumption, the reservation is also expired. |
| No blocking | Reservations do not block other operations. If a reservation is active, only that exact resource quantity is unavailable; other resources are unaffected. |

If an entity holds multiple reservations and exceeds its budget, the oldest reservation is expired first.

## Reservation TTL

| Context | Default TTL | Rationale |
|---------|-------------|-----------|
| Interactive execution | 60 seconds | User-facing operations complete quickly |
| Batch execution | 5 minutes | Longer-running operations need more setup time |
| Mission execution | 15 minutes | Mission coordination may take longer |
| Organization operation | 30 minutes | Organization-level operations may involve multiple entities |

TTL is configurable per entity type via RMP (007-RMP).

## Reservation and Budget Interaction

```
Reservation created:
    budget.reserved += reservation.resources
    budget.available = budget.total - budget.used - budget.reserved

Reservation consumed:
    budget.reserved -= reservation.resources
    budget.used += allocated_resources

Reservation expired/released:
    budget.reserved -= reservation.resources
    budget.available = budget.total - budget.used
```

Reservations consume budget capacity during their active lifetime. Entities with large active reservations will have less budget available for other operations.

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| ReservationCreated | createReservation | reservation_id, entity_id, capability_id, resources, ttl, expires_at, timestamp |
| ReservationConsumed | consumeReservation | reservation_id, entity_id, allocation_id, timestamp |
| ReservationReleased | releaseReservation | reservation_id, entity_id, reason, timestamp |
| ReservationExpired | TTL expiry | reservation_id, entity_id, timestamp |
| ReservationScanCompleted | Periodic scan | expired_count, released_count, timestamp |

## Cross-Cutting Concerns

### Security

Reservations require entity authentication and capability authorization. Reservation consumption requires matching execution token.

### Evidence

All reservation operations produce Events. Complete reservation lifecycle is auditable.

### Lifecycle

Reservation lifecycle is tightly coupled to execution lifecycle. When an entity terminates, all active reservations for that entity are released via Recovery (012-Recovery).

### Capability Bounds

Reservation resource quantities cannot exceed the capability's maximum resource envelope as defined in the capability template.

### Communication

Reservation operations are synchronous with the verification pipeline. Reservation creation happens inline during Stage 7. Expiry scanning is asynchronous.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Reservation handles only resource holding for execution authorization. Separate from general allocation. |
| R9 — Deterministic | Reservation logic is deterministic — same inputs always produce same reservation outcome (or same insufficient-resources denial). |
| R10 — Simpler Over Complex | Time-bound TTL is the sole deadlock prevention mechanism. No complex locking or transaction protocols. |
| R13 — Design for Failure | Automatic expiry prevents deadlocks. If the Reservation Manager crashes, resources are still released on TTL expiry via a background watcher. |
| R14 — Paved Path | The paved path is: Verification Pipeline → Reserve → Execute → Consume → Release. No other path. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Reservation converts to allocation on consumption |
| ROS/005-Budget.md | Reservation consumes budget capacity |
| ROS/006-Quota.md | Reservation checked against quota |
| ROS/012-Recovery.md | Recovery releases reservations on entity failure |
| Physics/010-Execution.md | Stage 7 of verification pipeline triggers reservation |
| Physics/006-Lifecycles.md | Execution lifecycle binds reservation lifecycle |
