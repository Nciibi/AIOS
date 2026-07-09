# AIOS Bible — Foundations
## 005 — Architectural Patterns

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-005 |
| Source Laws | All — Patterns operationalise Laws into reusable design |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## 1. Event Sourcing

**Pattern**: State is a projection of an append-only event log. Current state is derived by replaying events in order.

**Where Used**: IDS (identity events), Event Store (all system events), lifecycle management (state transitions as events)

**Benefits**:
- Complete audit trail — every state change is an event
- Point-in-time reconstruction — replay events from any point
- Immutable — events cannot be modified or deleted
- Event-driven integrations — other services consume event streams

**Implementation**:
- Events are immutable records with a type, payload, timestamp, and predecessor hash
- Current state is computed from the event log using a fold/reduce
- Snapshotting compresses long event chains for performance (every N events)
- Event store is append-only with no delete or update operations

## 2. Pipeline Pattern

**Pattern:** A linear, sequential chain of stages. Each stage transforms input and passes to the next stage. Any stage may deny, terminating the pipeline.

**Used Where**: Security Council verification pipeline (7 stages), action execution pipeline

**Benefits**:
- Fail-fast — denial at any stage prevents unnecessary work
- Deterministic — same inputs always produce same result
- Auditable — each stage produces a result event
- Testable — each stage can be tested in isolation
- Extensible (R15) — new stages can be added without modifying existing ones

**Invariants**:
- Stages execute in fixed order
- No stage may be skipped
- Each stage receives the cumulative context
- A denial terminates the pipeline immediately

## 3. Builder Pattern

**Pattern:** Complex objects are constructed by a dedicated builder. The client receives a fully-validated, ready-to-use object.

**Used Where**: Identity Factory (IDS), Token Factory (ATS), Genome instantiation (AGS)

**Benefits**:
- Construction and use are separated (R4)
- Validation occurs at construction time, not use time
- The client cannot create invalid objects
- The builder can enforce cross-field invariants

**Implementation**:
- Builders are the only way to create instances
- Builders validate all invariants before returning the object
- Builders may return errors with unique codes (R12)
- Once constructed, objects are immutable where specified

## 4. Dependency Injection

**Pattern:** Dependencies are passed to a module through its constructor or initialiser, rather than resolved from global state or static factories.

**Used Where**: Security Council (injects IDS, ATS, AZS, Policy, CCA, Risk, ROS), pipeline stages, Engine services

**Benefits**:
- Modules are testable in isolation (R6, R7)
- Dependencies are explicit, not hidden in global state
- Failures are detected at construction time, not at usage time
- Parallel development — teams can work on different modules independently

**Implementation**:
- Dependencies are injected through the constructor as interfaces/traits
- The composition root wires up all dependencies at startup
- Singletons are injected, not accessed as static state

## 5. CQRS (Command Query Responsibility Segregation)

**Pattern:** Write operations (commands) and read operations (queries) use separate models. Commands produce events; queries read projections.

**Used Where**: IDS Registry Store (append-only event log + query projection), Event Store (commands produce events, queried through API)

**Benefits**:
- Read and write paths can be optimised independently
- Event sourcing is naturally CQRS (events are commands, projections are reads)
- Read replicas can be scaled separately from write primaries

## 6. State Machine Pattern

**Pattern:** Every constitutional entity has a finite set of states and a finite set of authorised transitions between them. Transitions produce events and require authorisation.

**Used Where**: LMS, entity lifecycle management, identity lifecycle, Mission lifecycle

**Implementation**:
- States are enumerated values
- Transitions are defined as a matrix: `(current_state, target_state) → authorized_entity`
- The Lifecycle Management Service (LMS) enforces valid transitions
- Invalid transitions are denied with a specific error code

## 7. Observability via Events

**Pattern:** All system observability (metrics, logs, traces) is derived from the Event Store, not from separate instrumentation. Every operation produces an Event, and observability tools consume those Events.

**Used Where**: Every service — all produce Events on every operation

**Benefits**:
- Single source of truth for observability
- No separate logging infrastructure needed
- Events are structured and queryable
- Historical analysis is trivial (replay old Events)

## 8. Strangler Fig Pattern

**Pattern:** Legacy functionality is gradually replaced by new functionality, running both in parallel until the new implementation fully replaces the old.

**Used Where**: System evolutions, RFC-based migrations, service replacements

**Benefits**:
- Low-risk migration (rollback is always possible)
- Gradual adoption without big-bang deployment
- A/B testing of new vs old implementations
- Constitutional consistency throughout transition