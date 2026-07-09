# AIOS Bible — Core
## AGS 001 — Genome Composition

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-AGS-001 |
| Source Laws | Law 5 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/004-Sessions.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Genome Composition defines how entity templates are constructed from base definitions, inherited traits, and overrides. Composition is the process that transforms a template_id and optional overrides into a concrete, validated Genome ready for signing and instantiation.

## Composition Model

Genome composition follows a layered model:

```
Base Genome (constitutional root)
    │
    ▼
Inherited Traits (from parent Genome(s))
    │
    ▼
Overridden Traits (explicit overrides at composition time)
    │
    ▼
Composed Genome (concrete, validated, signable)
```

| Layer | Source | Description |
|-------|--------|-------------|
| Base Genome | AGS Registry | The constitutional root definition for the entity type |
| Inherited Traits | Parent Genome(s) | Traits inherited from the parent in the inheritance chain |
| Overridden Traits | Composition request | Explicit overrides provided at composition time |
| Composed Genome | Composition result | The complete, validated Genome ready for signing |

## Genome Schema for Composition

A Genome at composition time has this schema:

| Field | Type | Composed From |
|-------|------|---------------|
| genome_id | UUID | Assigned by AGS |
| base_type | enum | Base Genome (Worker, User, Engine, Organization, Mission) |
| template_id | UUID | Source template reference |
| capabilities | Capability[] | Inherited from parent, possibly restricted by overrides |
| capability_bounds | Bound[] | Inherited from parent, possibly restricted by overrides |
| policies | PolicyRef[] | Inherited from parent, possibly overridden |
| constraints | Constraint[] | Inherited from parent (cannot be overridden for constitutional traits) |
| inheritance_chain | UUID[] | Complete path from base to current |
| overrides_applied | Override[] | Record of all overrides applied during composition |
| provenance | Provenance | Creator, timestamp, authorization proof |

## Composition Example

Base Worker Genome (Worker type):
```
capabilities: [communicate, execute, report]
capability_bounds: { max_concurrent: 5, max_duration: 3600s }
policies: [default_security, default_privacy]
```

Request: Compose WOM (Worker Operation Manager) with override:
```
overrides: {
  capability_bounds: { max_concurrent: 3 }  // restricted from 5
}
```

Result (Composed WOM Genome):
```
capabilities: [communicate, execute, report]
capability_bounds: { max_concurrent: 3, max_duration: 3600s }  // max_concurrent restricted
policies: [default_security, default_privacy, wom_policy]
```

The override `max_concurrent: 3` is valid because it restricts (3 < 5). An override of `max_concurrent: 10` would be invalid because it expands (10 > 5).

## Composition Rules

### Rule 1 — Override Must Not Expand

A child Genome may restrict but NOT expand parent capabilities. This is the constitutional safety principle — inheritance can only tighten, not loosen, capability bounds.

```
Parent: capabilities = [read, write, execute]
Child:  capabilities = [read, write]        ✓ VALID (restricted)
Child:  capabilities = [read, write, admin]  ✗ INVALID (expanded)
```

### Rule 2 — No Circular Inheritance

Genome inheritance must be a directed acyclic graph (DAG). Circular inheritance is detected and rejected during composition.

### Rule 3 — Complete Override

When a trait is overridden, the override must provide a complete definition for that trait. Partial overrides are not permitted — the inheriting Genome specifies the complete trait or inherits it entirely.

### Rule 4 — Constitutional Compliance

The composed Genome must pass constitutional compliance validation (CPR-009). Composition may complete but the Genome will fail at the validation stage (AGS/003-Validation.md) if it violates a constitutional constraint.

## Composition Operations

### compose(template_id, overrides)

```
Input:  template_id (the base Genome to start from), overrides (optional trait overrides)
Process:
  1. Load base Genome from Registry
  2. Resolve inheritance chain
  3. Apply inherited traits
  4. Validate overrides (Rule 1, Rule 3)
  5. Apply valid overrides
  6. Produce composed Genome
Output: ComposedGenome { genome_id, template_id, traits, overrides_applied, inheritance_chain }
Event: AGS.GenomeComposed
```

### inherit(parent_genome_id)

```
Input:  parent_genome_id
Process:
  1. Load parent Genome
  2. Verify no circular inheritance (Rule 2)
  3. Copy all traits from parent
  4. Return inheritable traits
Output: InheritedTraits { parent_id, traits, inheritance_depth }
```

### merge(genome_a, genome_b)

```
Input:  genome_a, genome_b (two Genomes to merge)
Process:
  1. Validate compatibility (same base type)
  2. Resolve trait conflicts (genome_a takes priority)
  3. Merge capability sets (intersection — most restrictive)
  4. Merge policy sets (union with conflict resolution)
  5. Produce merged Genome
Output: MergedGenome { genome_id, sources: [a_id, b_id], merged_traits }
Note: merge is for administrative use only — standard composition uses compose()
```

## Override Validation

| Check | Description | Error Code |
|-------|-------------|------------|
| Capability Expansion | Override must not expand parent capabilities | AGS_CMP_001 |
| Partial Override | Override must provide complete trait definition | AGS_CMP_002 |
| Circular Inheritance | Inheritance chain must be acyclic | AGS_CMP_003 |
| Type Compatibility | Override must match trait type signature | AGS_CMP_004 |
| Constitutional Compliance | Override must not violate Laws | AGS_CMP_005 |

## Composition Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `AGS.GenomeComposed` | Genome composition completes | genome_id, template_id, override_count |
| `AGS.GenomeInherited` | A parent Genome's traits are inherited | child_id, parent_id, depth |
| `AGS.GenomeMerged` | Two Genomes are merged | genome_id, source_a, source_b |
| `AGS.CompositionFailed` | Composition fails validation | template_id, error_code, error_message |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| AGS_CMP_001 | Override expands parent capabilities — violation of Rule 1 |
| AGS_CMP_002 | Override provides partial trait definition — violation of Rule 3 |
| AGS_CMP_003 | Circular inheritance detected — violation of Rule 2 |
| AGS_CMP_004 | Override type mismatch with trait definition |
| AGS_CMP_005 | Override fails constitutional compliance check |
| AGS_CMP_006 | Template not found in Registry |

## Cross-Cutting Concerns

### Security

Composition is a constitutional operation. Every composition is recorded as an Event. Composed Genomes are immutable after composition — they cannot be altered without creating a new version. (Physics/008-Security.md)

### Evidence

Every composition operation produces an Event. The complete composition path (template → inheritance → overrides → result) is recorded for audit. (PHI-008)

### Lifecycle

Composition transitions a Genome from Draft to Composed state. The Genome is then ready for Validation (AGS/003). (Physics/006-Lifecycles.md)

### Capability Bounds

Composition enforces the constitutional safety principle — capabilities can only be restricted, never expanded. This is fundamental to AIOS security model. (Physics/007-Capabilities.md)

### Communication

Composition requests arrive via ACF from authorized entities (Sou, Security Council, Organization administrators). Results are returned via ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Composition focused solely on building Genomes from parts |
| R3 (DRY) | Inheritance prevents duplication — traits defined once, inherited many times |
| R4 (Builder) | Composition is the builder step — separate from validation and execution |
| R10 (Simpler Over Complex) | Composition uses linear inheritance chain, not complex mixin graphs |
| R12 (Embrace Errors) | All composition errors have unique codes (AGS_CMP_001–006) |
| R15 (Open/Closed) | New Genome types can be added without modifying composition logic |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/004-Sessions.md | Sessions — composed Genomes define Session capabilities |
| Physics/007-Capabilities.md | Capabilities — Genomes define capability bounds |
| Bible/02-Core/AGS/000-Overview.md | AGS overview — composition is a core AGS operation |
| Bible/02-Core/AGS/002-Inheritance.md | Inheritance — composition relies on inheritance hierarchy |
| Bible/02-Core/AGS/003-Validation.md | Validation — composed Genomes must be validated |
| Bible/02-Core/AGS/005-Signing.md | Signing — validated Genomes are signed |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
