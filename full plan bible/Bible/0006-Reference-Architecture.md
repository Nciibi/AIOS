# AIOS Bible
## 0006 — Reference Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Root |
| Document ID | AIOS-BBL-0006 |
| Source Laws | All Laws — Reference architecture catalogs patterns and decisions |
| Source Physics | Physics/000-Laws.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Reference Architecture catalogs the architectural patterns, decision records, and design standards used across AIOS. It serves as the authoritative reference for architects and developers when making design decisions. Every pattern in this catalog has been reviewed by the ADG and approved for use across the platform.

## Architecture Decision Records

Architecture Decision Records (ADRs) are the primary mechanism for documenting significant architectural decisions. Each ADR captures the context, decision, alternatives, and consequences.

### ADR Lifecycle

```
Identified → Drafted → Reviewed → Approved → Recorded → Maintained → Superseded
```

| Stage | Activities | Participants |
|-------|-----------|--------------|
| Identified | Architectural need recognized | Any entity |
| Drafted | ADR written in standard format | Proposer |
| Reviewed | ADG reviews for Design DNA compliance | ADG Review Board |
| Approved | Decision accepted | ADG Review Board |
| Recorded | Stored in CKR | CKR |
| Maintained | Updated if context changes | Designated owner |
| Superseded | Replaced by newer ADR | ADG Review Board |

### ADR Index (Complete)

| ID | Title | Status | Date |
|----|-------|--------|------|
| ADR-0001 | ACF as Universal Communication Backbone | Approved | 2026-01-15 |
| ADR-0002 | Event Store as Single Source of Truth | Approved | 2026-01-20 |
| ADR-0003 | Seven-Stage Security Pipeline | Approved | 2026-02-01 |
| ADR-0004 | State Machine as Universal Lifecycle Model | Approved | 2026-02-10 |
| ADR-0005 | IRS as Single Identity Authority | Approved | 2026-02-15 |
| ADR-0006 | Separation of Sou and OSYS | Approved | 2026-03-01 |
| ADR-0007 | Capability Bounds as Declared Properties | Approved | 2026-03-10 |
| ADR-0008 | Autonomy Levels L0–L4 | Approved | 2026-03-20 |
| ADR-0009 | SDK-Based Runtime Interface | Approved | 2026-04-01 |
| ADR-0010 | Academy Learning from Evidence Only | Approved | 2026-04-10 |
| ADR-0011 | Organization Hierarchy Depth | Approved | 2026-04-15 |
| ADR-0012 | Event Retention Tiering | Approved | 2026-04-20 |
| ADR-0013 | Plugin Sandbox Architecture | Proposed | 2026-04-25 |

## Patterns Catalog

### Structural Patterns

#### Pattern S-001: Modulsingular Service

**Context**: A service should have exactly one responsibility.

**Solution**: Decompose services by single responsibility. Each service:
- Has exactly one domain of concern
- Exposes a cohesive set of operations
- Can be described in one sentence without "and" or "but"
- Is independently deployable and versionable

**Example**: ACF Routing handles message routing only. CSP handles cryptography only. Neither handles both.

**Design DNA**: R1 (Modulsingularity)

**Used By**: All services in volume 06-Services.

#### Pattern S-002: Layered Architecture

**Context**: System components must be organized by dependency order.

**Solution**: Organize components into layers where each layer depends only on layers below. The canonical layer order:
1. Governance (CLS, DGP, CRP, ADG)
2. Core Engine (Sou, Academy, OSYS, ROS)
3. Security (Security Kernel, Security Council)
4. Infrastructure (LMS, Event Store, ACF, CSP)
5. Runtime (Worker Runtimes, SDKs)

**Design DNA**: R2 (Dependency Order)

**Used By**: Entire AIOS platform.

#### Pattern S-003: Builder Pattern

**Context**: Complex objects should be constructed separately from their use.

**Solution**: Use builders to construct complex objects. Builders validate and assemble components. Clients receive fully constructed, validated objects.

**Example**: Identity Factory builds identity records. Token Factory builds authentication tokens. Capability Builder constructs capability certificates.

**Design DNA**: R4 (Builder Pattern)

**Used By**: IRS (identity construction), CCA (capability certification).

### Behavioral Patterns

#### Pattern B-001: Event Sourcing

**Context**: System state must be auditable and recoverable.

**Solution**: All state changes are recorded as Events in an append-only Event Store. Current state is derived by replaying Events. State is never modified in place.

**Benefits**:
- Complete audit trail
- Time-travel debugging
- Event-driven recovery
- Historical state reconstruction

**Design DNA**: R3 (DRY — state is derived, not duplicated)

**Used By**: EVS, LMS, all entity state management.

#### Pattern B-002: Pipeline Pattern

**Context**: Multi-stage processing where stages are sequential and dependent.

**Solution**: Organize processing as a linear sequence of stages. Each stage receives input, processes it, and passes output to the next stage. Stages are independent modules that can be tested and improved separately.

**Examples**:
- Security Kernel: Identity → Authentication → Authorization → Policy → Capability → Risk → ExecutionAuth
- Academy: Collection → Filtering → Analysis → Validation → Storage
- RFC: Draft → Review → Approval → Implementation → Verification

**Design DNA**: R1 (each stage does one thing), R2 (pipeline is acyclic)

**Used By**: Security Kernel, Academy, CRP.

#### Pattern B-003: Saga Pattern

**Context**: Distributed transactions spanning multiple services.

**Solution**: Define compensating actions for each step. If a step fails, execute compensating actions for all completed steps. Use a saga coordinator to track progress.

**Benefits**:
- No distributed locks
- Eventual consistency
- Graceful failure handling

**Design DNA**: R13 (Design for Failure)

**Used By**: Worker creation, Mission execution, Organization lifecycle.

### Communication Patterns

#### Pattern C-001: Request-Response

**Context**: Synchronous communication where the caller expects a response.

**Solution**: Request published to service-specific topic. Response published to caller-specific topic. Correlation ID links request and response.

**Used By**: Identity verification, authorization checks, knowledge queries.

#### Pattern C-002: Publish-Subscribe

**Context**: One-to-many event distribution.

**Solution**: Publisher writes to a topic. ACF delivers to all subscribers. Subscribers register interest via subscription.

**Used By**: Lifecycle state transitions, evidence events, governance decisions.

#### Pattern C-003: Streaming

**Context**: Continuous ordered data flow.

**Solution**: ACF Streaming extension provides ordered, partitioned streams with cursor management. Consumers maintain position and can replay.

**Used By**: Real-time monitoring, knowledge feeds, cross-instance replication.

### Security Patterns

#### Pattern SEC-001: Verification-First

**Context**: Every action must be verified before execution.

**Solution**: Seven-stage verification pipeline. Every action passes through all stages before receiving an Execution Authorization Token. No action executes without a valid token.

**Design DNA**: R14 (Paved Path — the pipeline is the only path to execution)

**Used By**: All entity actions.

#### Pattern SEC-002: Capability-Based Access Control

**Context**: Access control based on declared capabilities rather than roles.

**Solution**: Each entity declares its capabilities at creation. The Security Kernel verifies every action against declared capabilities. Capabilities are bounded and time-limited.

**Design DNA**: R7 (Capability Bounds — capabilities are bounded by declaration)

**Used By**: All Workers, Plugins, Providers.

#### Pattern SEC-003: Identity-First Authentication

**Context**: Identity must be verified before authentication can proceed.

**Solution**: The Security Pipeline starts with identity verification (IRS lookup). Only after identity is confirmed does authentication proceed. Authentication proves ownership of the identity.

**Design DNA**: R2 (Identity precedes authentication in the dependency order)

**Used By**: All authentication flows.

### Resilience Patterns

#### Pattern R-001: Circuit Breaker

**Context**: Failure in a dependent service should not cascade.

**Solution**: Each service call is wrapped in a circuit breaker. If failures exceed a threshold, the circuit opens and calls fail fast. Periodic health checks close the circuit when the service recovers.

**Design DNA**: R13 (Design for Failure)

**Used By**: All inter-service calls.

#### Pattern R-002: Bulkhead

**Context**: Resources should be isolated to prevent one consumer from exhausting shared resources.

**Solution**: Resource pools are partitioned. Each entity or entity group has a dedicated resource pool. Exhaustion in one partition does not affect others.

**Design DNA**: R13 (Design for Failure)

**Used By**: ROS (resource allocation), Runtime (Worker execution).

#### Pattern R-003: Graceful Degradation

**Context**: System should continue operating with reduced functionality when components fail.

**Solution**: Critical functions have fallback modes. Non-critical functions are disabled gracefully. Users experience reduced functionality, not complete failure.

**Design DNA**: R13 (Design for Failure)

**Used By**: All platform components.

## Design Standards

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Service | Three-letter acronym | ACF, CSP, LMS |
| Entity Type | PascalCase | Organization, Worker, Mission |
| Capability | PascalCase | ExecuteAction, ManageSession |
| Event Type | PascalCase with domain prefix | ACF.MessageSent, LMS.StateTransition |
| ACF Topic | Lowercase with dots | aios.security.kernel.verify |
| Document ID | AIOS-BBL-XXX-XXX | AIOS-BBL-001-001 |

### Error Handling

- Every error has a unique error code: `SERVICE_NNN`
- Errors are structured: `{ code, message, details, correlation_id }`
- Errors are evidenced in the Event Store
- Critical errors trigger Security Council notification
- Error messages must not leak sensitive information

### Logging and Observability

- All service operations are logged
- Logs include correlation ID for request tracing
- Structured logging format (JSON)
- Log levels: DEBUG, INFO, WARN, ERROR, FATAL
- Log aggregation through ACF
- Metrics exported for monitoring

## Related Documents

| Document | Relationship |
|---------|-------------|
| 0003-Platform-Architecture.md | Platform architecture — these patterns are used in the platform |
| 0004-Service-Architecture.md | Service architecture — service interaction patterns |
| 0005-Domain-Architecture.md | Domain architecture — domain entity patterns |
| 09-Reference/000-Decision-Log.md | ADR log — detailed ADR entries |
| 09-Reference/002-ADG-Index.md | ADG index — architectural decisions indexed here |
| 00-Foundations/002-Design-DNA.md | Design DNA — patterns must comply with R1–R15 |
| 00-Foundations/005-Architectural-Patterns.md | Architectural patterns — extended pattern documentation |
| 00-Foundations/006-Design-Rules.md | Design rules — detailed design standards |
