# AIOS Bible — Core
## AGS 003 — Genome Validation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-AGS-003 |
| Source Laws | Law 5 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/001-Identity.md, Physics/004-Sessions.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Genome Validation ensures every Genome is structurally complete, constitutionally compliant, internally consistent, and properly sourced before it can be signed and used for Session instantiation. Validation is the gate through which every Genome must pass.

Validation is governed by Law 8 — Verification-First. No Genome may be signed or instantiated without passing all validation stages.

## Validation Pipeline

Validation is a linear, sequential pipeline of 5 stages:

```
Genome (composed)
    │
    ▼
Stage 1: Structure ──► Is the Genome structurally well-formed?
    │
    ▼
Stage 2: Semantics ──► Are all required fields present and valid?
    │
    ▼
Stage 3: Constitutional ──► Does the Genome comply with all Laws?
    │
    ▼
Stage 4: Consistency ──► Are there any contradictory traits?
    │
    ▼
Stage 5: Provenance ──► Is the source valid and traceable?
    │
    ▼
ValidationResult { passed: bool, errors[], warnings[] }
```

## Validation Stages

### Stage 1 — Structure Validation

Checks that the Genome conforms to the required schema format.

| Check | Description | Error Code |
|-------|-------------|------------|
| JSON validity | Genome payload is valid structured data | AGS_VAL_001 |
| Schema conformance | Genome follows the constitutional Genome schema | AGS_VAL_002 |
| Field types | All fields have correct data types | AGS_VAL_003 |
| Required sections | All mandatory sections are present (capabilities, bounds, policies) | AGS_VAL_004 |

### Stage 2 — Semantic Validation

Checks that all required fields contain valid and meaningful values.

| Check | Description | Error Code |
|-------|-------------|------------|
| Capability validity | All referenced capabilities exist in the Capability Registry | AGS_VAL_010 |
| Bound validity | Capability bounds are within constitutional limits | AGS_VAL_011 |
| Policy validity | All policies reference valid Policy Registry entries | AGS_VAL_012 |
| Genome type validity | genome_type is one of the five base types | AGS_VAL_013 |

### Stage 3 — Constitutional Validation

Checks that the Genome complies with all Laws and constitutional principles.

| Check | Description | Error Code |
|-------|-------------|------------|
| Law compliance | No capability or policy violates a Law | AGS_VAL_020 |
| Autonomy level | Autonomy level (L0–L4) is appropriate for the Genome type | AGS_VAL_021 |
| Capability bounds | All bounds are at least as strict as constitutional minimum | AGS_VAL_022 |
| Privacy compliance | Genome policies comply with CPR-010 | AGS_VAL_023 |

### Stage 4 — Consistency Validation

Checks for internal contradictions and conflicting traits.

| Check | Description | Error Code |
|-------|-------------|------------|
| No conflicting capabilities | Two capabilities do not have contradictory bounds | AGS_VAL_030 |
| No conflicting policies | Policies do not conflict with each other | AGS_VAL_031 |
| Policy-capability alignment | Policies do not contradict capability bounds | AGS_VAL_032 |
| Inheritance consistency | Overrides do not conflict with inherited traits | AGS_VAL_033 |

### Stage 5 — Provenance Validation

Checks the source and chain of custody of the Genome.

| Check | Description | Error Code |
|-------|-------------|------------|
| Valid creator | Creating entity is authorized to create Genomes | AGS_VAL_040 |
| Source traceability | Complete provenance chain from base to composed | AGS_VAL_041 |
| Timestamp validity | Creation timestamps are within acceptable range | AGS_VAL_042 |
| Authorization proof | Creator had authority to create this Genome type | AGS_VAL_043 |

## Validation Result

Every validation produces a structured result:

```
ValidationResult {
  passed: bool,                          // true if ALL checks pass
  errors: ValidationError[],             // blocking errors
  warnings: string[],                    // non-blocking concerns
  summary: {                             // per-stage summary
    structure: { passed: bool, error_count: int },
    semantics: { passed: bool, error_count: int },
    constitutional: { passed: bool, error_count: int },
    consistency: { passed: bool, error_count: int },
    provenance: { passed: bool, error_count: int }
  }
}
```

A Genome may pass with warnings. A Genome with any error at any stage does NOT pass.

## Validation Operations

### validateGenome(genome_id)

```
Input:  genome_id
Process: run all 5 pipeline stages sequentially
Output: ValidationResult
Event: AGS.GenomeValidated { passed, error_count, warning_count }
```

### validateOverride(genome_id, override_trait)

```
Input:  genome_id, override_trait (a single override)
Process: run consistency and constitutional checks on the override
Output: OverrideValidationResult { valid: bool, errors[], warnings[] }
```

### getValidationHistory(genome_id)

```
Input:  genome_id
Process: query Event Store for all validation Events for this Genome
Output: ValidationHistoryEntry[]
```

## Validation Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `AGS.ValidationStarted` | Validation pipeline begins | genome_id, stages_requested |
| `AGS.GenomeValidated` | Validation completes | genome_id, passed, error_count, warning_count |
| `AGS.ValidationStagePassed` | A single stage passes | genome_id, stage_name |
| `AGS.ValidationStageFailed` | A single stage fails | genome_id, stage_name, error_code |
| `AGS.ValidationOverrideChecked` | An override is validated | genome_id, override_trait, valid |

## Error Codes (R12)

| Code | Stage | Description |
|------|-------|-------------|
| AGS_VAL_001 | 1-Structure | Invalid Genome JSON format |
| AGS_VAL_002 | 1-Structure | Schema conformance failure |
| AGS_VAL_003 | 1-Structure | Field type mismatch |
| AGS_VAL_004 | 1-Structure | Missing required section |
| AGS_VAL_010 | 2-Semantics | Unknown capability reference |
| AGS_VAL_011 | 2-Semantics | Capability bound exceeds constitutional limit |
| AGS_VAL_012 | 2-Semantics | Unknown policy reference |
| AGS_VAL_013 | 2-Semantics | Invalid Genome type |
| AGS_VAL_020 | 3-Constitutional | Law violation in Genome definition |
| AGS_VAL_021 | 3-Constitutional | Autonomy level inappropriate for type |
| AGS_VAL_022 | 3-Constitutional | Capability bound below constitutional minimum |
| AGS_VAL_023 | 3-Constitutional | Privacy policy violation (CPR-010) |
| AGS_VAL_030 | 4-Consistency | Conflicting capability bounds |
| AGS_VAL_031 | 4-Consistency | Conflicting policies |
| AGS_VAL_032 | 4-Consistency | Policy contradicts capability bound |
| AGS_VAL_033 | 4-Consistency | Override conflicts with inherited trait |
| AGS_VAL_040 | 5-Provenance | Creator not authorized for Genome creation |
| AGS_VAL_041 | 5-Provenance | Incomplete provenance chain |
| AGS_VAL_042 | 5-Provenance | Invalid timestamp in provenance |
| AGS_VAL_043 | 5-Provenance | Missing authorization proof |

## Cross-Cutting Concerns

### Security

Validation is a constitutional gate. No Genome may bypass validation. The Security Council relies on AGS validation results before authorizing Session instantiation. (Physics/008-Security.md, Law 8)

### Evidence

Every validation operation produces Events. The complete validation history of every Genome is recorded for audit. (PHI-008)

### Lifecycle

Validation transitions a Genome from Composed to Validated state. A validated Genome is eligible for signing (AGS/005). A Genome that fails validation returns to Draft. (Physics/006-Lifecycles.md)

### Capability Bounds

Validation enforces all capability bounds. A Genome defining capabilities outside bounds is rejected. (Physics/007-Capabilities.md)

### Communication

Validation requests arrive via ACF. Results are returned via ACF. Validation Events are published to the Event Store through ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Validation focused solely on Genome correctness |
| R10 (Simpler Over Complex) | Linear 5-stage pipeline — no branching, no parallelism |
| R12 (Embrace Errors) | Every error has a unique code (AGS_VAL_001–043) |
| R13 (Design for Failure) | Pipeline reports which stage failed — does not continue past failure |
| R14 (Paved Path) | Single paved path: structure → semantics → constitutional → consistency → provenance |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/001-Identity.md | Identity — validation checks Genome identity fields |
| Physics/004-Sessions.md | Sessions — validation ensures Session can be instantiated |
| Physics/007-Capabilities.md | Capabilities — validation checks all capability references |
| Bible/02-Core/AGS/000-Overview.md | AGS overview — validation is a core AGS operation |
| Bible/02-Core/AGS/001-Composition.md | Composition — validation checks composed Genomes |
| Bible/02-Core/AGS/002-Inheritance.md | Inheritance — validation checks inheritance rules |
| Bible/02-Core/AGS/004-Versioning.md | Versioning — each version must be re-validated |
| Bible/02-Core/AGS/005-Signing.md | Signing — validation must pass before signing |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
