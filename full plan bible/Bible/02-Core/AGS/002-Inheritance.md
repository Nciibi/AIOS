# AIOS Bible — Core
## AGS 002 — Genome Inheritance

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-AGS-002 |
| Source Laws | Law 5 — Law of Capability Bounds, Law 7 — Law of Identity |
| Source Physics | Physics/001-Identity.md, Physics/004-Sessions.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Genome Inheritance defines the hierarchy of entity templates in AIOS. Every Session is instantiated from a Genome that inherits from one of five base types: Worker, User, Engine, Organization, or Mission. Inheritance ensures constitutional consistency — all Sessions of the same type share foundational traits while allowing specialization.

## Base Genome Types

AIOS defines five constitutional base Genomes:

| Base Type | Description | Inherited By |
|-----------|-------------|--------------|
| Worker | Executing entity — performs actions within capability bounds | All Worker subtypes (WOM, WHS, WSS, WCS) |
| User | Human or external entity interacting with AIOS | All User subtypes (Human, API, Federation) |
| Engine | System engine — provides internal capabilities | All Engine subtypes (Sou, Academy, DTS, AGS) |
| Organization | Collective entity — owns missions and resources | All Organization subtypes (ORG, ODS, OHS, OOM) |
| Mission | Temporary entity — represents a mission instance | All Mission subtypes |

## Inheritance Hierarchy

```
Base Level (Level 0)        Domain Level (Level 1)     Specific Level (Level 2)
──────────────────────      ──────────────────────     ──────────────────────
Worker ◄──────────────────  WOM ◄───────────────────   WOM-Specific (by config)
  (core capabilities:        (operation manager)         (organization-specific WOM)
   execute, report,           capabilities + role
   communicate)               specific policies
                            WHS ◄───────────────────   WHS-Specific
                            (workflow handler)
                            WSS                           WSS-Specific
                            (sub-workflow session)
                            WCS                           WCS-Specific
                            (workflow control session)

User ◄────────────────────  Human ◄──────────────────   Human-Specific
  (core capabilities:        (authenticated human)        (organization-specific)
   authenticate,             API ◄───────────────────   API-Specific
   communicate,              (programmatic access)
   submit intent)            Federation ◄─────────────   Federation-Specific
                            (cross-system identity)

Engine ◄──────────────────  Sou ◄────────────────────   (Sou is a singleton)
  (core capabilities:        Academy ◄────────────────   Academy-Specific
   reason, learn,            DTS ◄────────────────────   DTS-Specific
   govern, validate)         AGS ◄────────────────────   AGS-Specific

Organization ◄────────────  ORG ◄────────────────────   ORG-Specific
  (core capabilities:        ODS ◄────────────────────   ODS-Specific
   own missions,             OHS ◄────────────────────   OHS-Specific
   manage resources,         OOM ◄────────────────────   OOM-Specific
   govern members)

Mission ◄──────────────────  (by type) ◄──────────────   (mission-specific)
  (core capabilities:
   receive intent,
   produce outcome)
```

## Inheritance Depth Limit

Inheritance is limited to a maximum of 3 levels:

| Level | Name | Description |
|-------|------|-------------|
| 0 | Base | Constitutional root — one of five base types |
| 1 | Domain | Type-specific specialization (e.g., WOM, Human, ORG) |
| 2 | Specific | Configuration-specific specialization |
| 3+ | ✗ Forbidden | Any further inheritance is rejected |

This limit ensures the inheritance tree remains manageable and auditable. Deeper customization is achieved through Genome composition (AGS/001-Composition.md) with overrides, not through inheritance.

## Base Genome Capabilities

Each base Genome defines the minimum capabilities for its type:

| Base Type | Minimum Capabilities | Constitutional Traits |
|-----------|---------------------|----------------------|
| Worker | communicate, execute, report, authenticate | source_laws = [Law5, Law7, Law8], min_autonomy = L1 |
| User | authenticate, communicate, submit_intent | source_laws = [Law0, Law1, Law7], min_autonomy = L0 |
| Engine | reason, learn, govern, validate, communicate | source_laws = [Law2, Law4, Law9], min_autonomy = L2 |
| Organization | own_missions, manage_resources, govern_members, communicate | source_laws = [Law1, Law5, Law6], min_autonomy = L2 |
| Mission | receive_intent, produce_outcome, report, communicate | source_laws = [Law1, Law6], min_autonomy = L0 |

## Inheritance Example

```
Base: Worker
  capabilities: [communicate, execute, report]
  bounds: { max_concurrent_tasks: 5, max_duration_sec: 3600 }

Domain: WOM (Worker Operations Manager) inherits Worker
  capabilities: [communicate, execute, report]
  + wom_capability: orchestrate
  bounds: { max_concurrent_tasks: 3, max_duration_sec: 3600 }
  (orchestrate is a new capability at Domain level — allowed)
  (max_concurrent_tasks restricted from 5 to 3 — allowed, Rule 1 satisfied)

Specific: WidgetWOM inherits WOM
  capabilities: [communicate, execute, report, orchestrate]
  bounds: { max_concurrent_tasks: 2, max_duration_sec: 1800 }
  (both further restricted — allowed, Rule 1 satisfied)
```

## Override Rules

### Rule 1 — Restrict, Never Expand

A derived Genome may restrict any capability of its parent. It may never add new capabilities, increase bounds, or relax constraints.

```
Parent:  max_concurrent_tasks = 10
Child:   max_concurrent_tasks = 5   ✓ VALID (restricted)
Child:   max_concurrent_tasks = 15  ✗ INVALID (expanded)
```

### Rule 2 — Inherit All, Override Some

A derived Genome inherits ALL traits from its parent. It may override some of them (following Rule 1). It may not skip inheritance of any trait.

### Rule 3 — No Deep Override of Constitutional Traits

Constitutional traits (source_laws, min_autonomy_level, required_policies) may not be overridden in Domain-level or Specific-level Genomes. They are fixed at the Base level.

## Edge Cases — Inheritance

| Scenario | Handling |
|----------|----------|
| Circular inheritance (A inherits B, B inherits A) | Detected at registration time. Rejected with AGS_INH_006. |
| Child inherits from parent at Level 2 | Allowed — depth = 3 (Base → Domain → Specific → child is Level 3 → limit reached). |
| Child attempts to inherit from two parents at different levels | Not supported — single inheritance only. Use merge() for administrative scenarios. |
| Parent Genome is updated after child is created | Child is NOT automatically updated. Child remains at the version it was composed from. |
| Override of a trait that was added in a minor version of the parent | Allowed — child may override any non-constitutional trait. |
| Base Genome is modified (constitutional amendment) | All derived Genomes must be re-validated. Existing Sessions may require migration. |
| Attempt to inherit from a Genome at Level 2 (Specific) | Allowed — but resulting Genome would be at Level 3 (max). Further inheritance prohibited. |

## Inheritance Operations

### getBaseGenome(genome_type)

```
Input:  genome_type (Worker | User | Engine | Organization | Mission)
Process: query Registry for base Genome of the given type
Output: BaseGenome { genome_id, type, core_traits, constitutional_traits }
```

### getDerivedGenomes(parent_genome_id)

```
Input:  parent_genome_id
Process: query Registry for all Genomes that inherit from the given parent
Output: DerivedGenomeList { parent_id, children: [{ id, name, level }] }
```

### getInheritanceChain(genome_id)

```
Input:  genome_id
Process: traverse parent references up to root Base Genome
Output: InheritanceChain { genome_id, chain: [{ level, genome_id, name }] }
```

## Inheritance Performance

| Metric | Target | Hard Limit |
|--------|--------|------------|
| getBaseGenome() | < 50ms | 200ms |
| getDerivedGenomes() | < 100ms | 500ms |
| getInheritanceChain() | < 50ms | 200ms |
| Inheritance registration time | < 100ms | 500ms |
| Maximum children per parent | 1000 | 5000 |
| Maximum inheritance chain length | 3 levels | 3 levels (constitutional limit) |

## Inheritance Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `AGS.InheritanceRegistered` | A derived Genome registers its parent | child_id, parent_id, inheritance_level |
| `AGS.InheritanceQueried` | Inheritance chain is queried | genome_id, chain_depth |
| `AGS.InheritanceViolation` | An override rule is violated | child_id, parent_id, violation_rule, details |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| AGS_INH_001 | Inheritance depth exceeds maximum (3 levels) |
| AGS_INH_002 | Derived Genome expands parent capability (Rule 1 violation) |
| AGS_INH_003 | Derived Genome skips required inheritance (Rule 2 violation) |
| AGS_INH_004 | Attempt to override constitutional trait (Rule 3 violation) |
| AGS_INH_005 | Parent Genome not found in Registry |
| AGS_INH_006 | Circular inheritance detected |

## Cross-Cutting Concerns

### Security

Inheritance enforces constitutional safety — capabilities only narrow, never widen. This is a security invariant. The Security Council audits all inheritance registrations. (Physics/008-Security.md)

### Evidence

Every inheritance relationship is recorded as an Event. The complete inheritance tree is reconstructable from Events. (PHI-008)

### Lifecycle

Base Genomes are permanent (immutable). Derived Genomes follow the standard Genome lifecycle (Draft → Composed → Validated → Signed → Active → Deprecated). (Physics/006-Lifecycles.md)

### Capability Bounds

Inheritance is the mechanism through which capability bounds propagate. Every entity's capabilities are bounded by its inheritance chain. (Physics/007-Capabilities.md)

### Communication

Inheritance definitions and queries flow through ACF. AGS Registry is the authoritative source. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Inheritance focused solely on parent-child Genome relationships |
| R2 (Dependency Order) | Inheritance is a DAG — parent must exist before child |
| R3 (DRY) | Base Genome traits defined once, inherited by all subtypes |
| R10 (Simpler Over Complex) | Maximum 3 levels — simple, auditable hierarchy |
| R12 (Embrace Errors) | All errors have unique codes (AGS_INH_001–006) |
| R15 (Open/Closed) | New derived Genomes can be added without modifying base types |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/001-Identity.md | Identity — Genomes define identity types |
| Physics/004-Sessions.md | Sessions — instantiated from derived Genomes |
| Physics/007-Capabilities.md | Capabilities — inheritance enforces capability bounds |
| Bible/02-Core/AGS/000-Overview.md | AGS overview — inheritance is a core AGS component |
| Bible/02-Core/AGS/001-Composition.md | Composition — inheritance feeds composition |
| Bible/02-Core/AGS/003-Validation.md | Validation — inheritance rules are validated |
| Bible/02-Core/AGS/005-Signing.md | Signing — inherited Genomes are signed |
| Bible/03-Institutions/Workers | Workers — Worker type hierarchy |
| Bible/03-Institutions/Organizations | Organizations — Organization type hierarchy |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
