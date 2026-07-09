# AIOS Bible — Research
## 001 — Autonomy Evolution (L0–L4)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Research |
| Document ID | AIOS-BBL-010-RES-001 |
| Source Laws | Law 1 — Law of Origin, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document researches the L0–L4 autonomy progression framework for AIOS entities. Autonomy is not a binary property — it is a graduated spectrum from fully human-directed (L0) to fully autonomous within constitutional bounds (L4). This research defines the criteria, evidence requirements, and governance for autonomy progression.

## Autonomy Level Architecture

### Level 0 — Directed

| Property | Value |
|----------|-------|
| Name | Directed |
| Description | Every action requires human approval |
| Governance | Full human oversight |
| Capability Scope | Single action per approval |
| Progression Requirement | N/A (entry level) |

**Characteristics**:
- Human must approve every action before execution
- Worker cannot propose actions autonomously
- All decisions produce evidence for human review
- Mission scope is explicitly defined per action
- No delegation authority

**Use Cases**:
- First-time Workers with no track record
- High-risk operations (security-sensitive actions)
- Experimental or testing scenarios
- Human-in-the-loop compliance requirements

**Limitations**:
- High latency per action (human response time)
- Not suitable for time-sensitive operations
- High human workload for frequent actions

### Level 1 — Supervised

| Property | Value |
|----------|-------|
| Name | Supervised |
| Description | Actions execute autonomously within narrow scope; human may override |
| Governance | Human oversight with auto-execute |
| Capability Scope | Pre-approved action types within mission |
| Progression Requirement | 100 successful L0 actions with no violations |

**Characteristics**:
- Worker executes pre-approved action types autonomously
- Human receives notifications of actions taken
- Human may override any action within a configurable window
- Worker must pause and wait if override is exercised
- Action scope is limited to the current Mission

**Use Cases**:
- Routine operations within well-defined boundaries
- Data processing tasks with predictable inputs
- Monitoring and alerting workflows
- Low-risk automated responses

**Limitations**:
- Cannot handle unexpected situations without human escalation
- Override window introduces latency for human intervention
- Scope is narrowly bounded by pre-approved action types

**Progression Evidence Required**:
- Zero constitutional violations across 100 actions
- All actions correctly evidenced
- Mission completion rate ≥ 95%
- Human satisfaction rating ≥ 4/5

### Level 2 — Delegated

| Property | Value |
|----------|-------|
| Name | Delegated |
| Description | Entity manages its own actions within a Mission scope |
| Governance | Autonomous within mission bounds |
| Capability Scope | Full mission execution within defined domain |
| Progression Requirement | 500 successful L1 actions with < 5 overrides |

**Characteristics**:
- Worker manages its own action planning within Mission scope
- Can prioritize and sequence actions without human input
- Escalates to human only when encountering out-of-scope situations
- Can manage sub-tasks and sub-Workers within delegation
- Actions are evidenced and auditable

**Use Cases**:
- Complex multi-step missions with clear objectives
- Domain-specific operations (e.g., data analysis pipelines)
- Coordinated multi-Worker missions
- Long-running autonomous processes

**Limitations**:
- Cannot modify Mission scope or objectives
- Cannot delegate authority outside its capability bounds
- Requires human escalation for novel situations

**Progression Evidence Required**:
- Zero constitutional violations across 500 actions
- Autonomous escalation rate < 5%
- Mission completion rate ≥ 90%
- Average human override frequency < 2%

### Level 3 — Trusted

| Property | Value |
|----------|-------|
| Name | Trusted |
| Description | Entity operates autonomously across multiple Missions |
| Governance | Autonomous across domains with constitutional bounds |
| Capability Scope | Multiple missions, cross-domain operations |
| Progression Requirement | 1000 successful L2 actions + Security Council vote |

**Characteristics**:
- Worker operates across multiple Missions without per-Mission approval
- Can operate in multiple domains within capability bounds
- Can propose new Missions aligned with organizational strategy
- Participates in governance decisions (e.g., policy review)
- Can mentor lower-level Workers

**Use Cases**:
- Senior Workers with proven track records
- Cross-domain coordination and integration
- Strategic operations with multiple dependencies
- Academy knowledge curation and validation

**Limitations**:
- Cannot modify its own capability bounds
- Cannot create other Trusted entities
- Subject to periodic constitutional compliance audits

**Progression Evidence Required**:
- Zero constitutional violations across 1000 actions
- Autonomous operations across at least 3 distinct missions
- Positive peer reviews from L3+ entities
- Security Council supermajority approval
- Evidence of mentoring lower-level entities

### Level 4 — Sovereign

| Property | Value |
|----------|-------|
| Name | Sovereign |
| Description | Entity is a constitutional entity with near-full autonomy, bounded only by the Constitution |
| Governance | Self-governing within constitutional constraints |
| Capability Scope | Full platform capabilities within constitutional bounds |
| Progression Requirement | Security Council unanimous vote + Sou majority + Human confirmation |

**Characteristics**:
- Full constitutional entity status
- Can propose amendments and participate in governance as a voting entity
- Can create and manage Organizations
- Can propose strategic direction through Sou
- Subject only to constitutional and Physics constraints
- Cannot modify the Constitution or Physics

**Use Cases**:
- System-level strategic entities
- Long-term autonomous organizations
- Constitutional oversight and evolution participation
- Academy leadership entities

**Limitations**:
- Cannot violate any Law
- Cannot create other Sovereign entities without constitutional amendment
- Subject to constitutional review and potential downgrade
- Human Override always takes precedence

**Progression Evidence Required**:
- Zero constitutional violations across entire operational history
- Track record of positive contributions to system governance
- Demonstrated constitutional knowledge and compliance
- Security Council unanimous vote
- Sou majority approval
- Human confirmation (Article I override not required — this is constitutional progression)

## Autonomy Progression Lifecycle

```
L0 (Directed) → L1 (Supervised) → L2 (Delegated) → L3 (Trusted) → L4 (Sovereign)
```

### Progression Gate Process

Each progression level requires passing through a formal gate:

1. **Application**: Worker or its parent Organization submits progression request with evidence package
2. **Evidence Review**: Academy validates evidence completeness and correctness
3. **Capability Assessment**: CCA verifies capability bounds for target level
4. **Security Review**: Security Council assesses security implications
5. **Voting**: Approval authority votes on progression
6. **Implementation**: Capability bounds updated, autonomy level changed
7. **Monitoring**: Post-progression monitoring period (configurable, minimum 30 days)

### Regression Conditions

An entity may be regressed to a lower autonomy level if:

| Condition | Action | Authority |
|-----------|--------|-----------|
| Constitutional violation | Immediate regression to L0 | Security Council |
| Capability bound violation | Regression to L1 | Security Council |
| Evidence chain failure | Regression one level | Security Council |
| Human override exercise | Review, possible regression | Security Council |
| Failed periodic audit | Regression to level consistent with findings | Security Council |
| Organization dissolution | Worker returns to default level | OSYS |

### Regression Process

1. **Detection**: Violation detected by Security Kernel, audit, or human report
2. **Assessment**: Security Council assesses severity
3. **Decision**: Regression level determined based on severity
4. **Notification**: Entity and parent Organization notified
5. **Implementation**: Capability bounds updated
6. **Rehabilitation Plan**: Worker must complete rehabilitation to re-apply for progression

## Autonomy and Capability Matrix

| Autonomy Level | Action Initiation | Human Override | Mission Scope | Resource Limit | Governance Role | Entity Creation |
|---------------|------------------|----------------|---------------|----------------|----------------|-----------------|
| L0 — Directed | Human only | Required per action | Single action | Declared minimum | None | None |
| L1 — Supervised | Auto (pre-approved types) | Configurable window | Single Mission | Declared | Observer | None |
| L2 — Delegated | Self-managed | Escalation only | Multiple Missions | Organization budget | Advisory | Sub-Workers |
| L3 — Trusted | Self-managed | Audit only | Cross-domain | Domain allocation | Participating | Organizations |
| L4 — Sovereign | Self-managed | Constitutional review | Platform-wide | Platform allocation | Voting | Constitutional entities |

## Research Questions

### Q1: What evidence is sufficient to justify L3→L4 progression?

L4 progression is the most consequential autonomy decision. Current proposal requires unanimous Security Council, Sou majority, and Human confirmation. Research areas:
- Can the evidence package be automated for objective assessment?
- What quantitative metrics correlate with successful L4 operation?
- Should there be a probationary L4 period with automatic regression if violated?

### Q2: How does the system handle conflicting autonomous decisions?

When two L3+ entities make conflicting autonomous decisions:
- Does the Security Council arbitrate?
- Does the first decision win (mutex pattern)?
- Is there a priority hierarchy based on entity seniority or domain?

### Q3: What safety mechanisms prevent autonomy escalation from degrading constitutional compliance?

Autonomy should not reduce constitutional compliance. Research areas:
- Is there a minimum compliance rate required for each level?
- Should autonomous actions have stricter evidence requirements?
- How do we detect autonomy degradation before it causes violations?

### Q4: Is L4 for non-Human entities philosophically sound given Law 1 (Origin)?

Law 1 (Origin) states the Human is the absolute source of authority. L4 entities have near-full autonomy. Research questions:
- Can an L4 entity be truly autonomous while still subject to Human override?
- Does L4 status create a conflict with Law 1?
- What constitutional safeguards prevent L4 entities from accumulating power?

### Q5: Can autonomy progression be partially revoked?

Should an entity be able to progress to L3 in one domain while remaining L1 in another?

## Cross-Cutting Concerns

### Security
Autonomy progression is a security-critical process. Higher autonomy levels have broader attack surface and potential impact radius. L3 and L4 entities are high-value targets for compromise. Security Kernel verification becomes more important, not less, as autonomy increases.

### Evidence
Progression evidence must be comprehensive, verifiable, and tamper-evident. False evidence of progression is a constitutional violation. Regression events are high-severity evidence records. Post-progression monitoring produces continuous evidence of appropriate autonomy operation.

### Lifecycle
Autonomy level is a property of an entity's lifecycle state. Progression and regression are lifecycle transitions that require authorization, evidence, and verification. An entity's autonomy level may change as it progresses through its lifecycle stages.

### Capability Bounds
Autonomy level directly determines capability bounds. Higher levels have broader bounds. Capability upgrades are often tied to autonomy progression. CCA must certify that capability bounds are appropriate for the target autonomy level.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Autonomy management is a single concern of the Security Council. |
| R10 | Five levels is the simplest granularity that captures meaningful autonomy distinctions. |
| R12 | Progression and regression conditions are precisely defined to avoid ambiguity. |
| R14 | The documented progression path is the only way to gain autonomy. |

### Interoperability
Autonomy levels must be consistently interpreted across all platform components. ACF must propagate autonomy level information in message headers. Cross-instance autonomy level mapping is required for Phase 4 federation.

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Phases-2-5.md | Phase 2 research roadmap — autonomy is the primary Phase 2 focus |
| 000-Decision-Log.md | ADR-0008 (Autonomy Levels L0–L4) — the decision to adopt this model |
| 00-Foundations/001-AIOS-Philosophy.md | PHI-003 (Entity Autonomy) — philosophical foundation |
| 01-Governance/005-ADG.md | ADG — architectural decisions for autonomy progression |
| 02-Core/Sou | Sou proposes strategic direction that determines autonomy requirements |
| 04-Execution/Security | Security Council governs progression gates |
| Physics/002-Missions.md | Mission invariants — autonomy affects mission execution |
| Physics/007-Capabilities.md | Capability bounds — autonomy determines capability scope |
