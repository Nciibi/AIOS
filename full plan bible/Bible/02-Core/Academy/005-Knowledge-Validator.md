# AIOS Bible — Core
## Academy — 005: Knowledge Validator

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-005 |
| Source Laws | Law 4 — Evidence, Law 9 — Deterministic |
| Source Physics | Physics/012-Experience.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge Validator is the first gate in the Academy validation pipeline. It ensures every proposed knowledge artifact meets constitutional, quality, and privacy standards before it proceeds to verification (006) and review (007). The Validator enforces the AKM validation rules defined in Governance/006-AKM.md.

## Validation Pipeline

The Validator runs as a multi-stage linear pipeline:

```
Proposed Knowledge
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  Stage 1: Schema Validation                          │
│  - Is the artifact structure valid?                  │
│  - Are required fields present?                      │
│  - Are field types correct?                          │
└──────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  Stage 2: Constitutional Consistency                 │
│  - Does the artifact violate any Law?                │
│  - Is it consistent with Physics invariants?         │
│  - Is it consistent with Foundations principles?     │
└──────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  Stage 3: Evidence Provenance                        │
│  - Are all source Event IDs valid?                   │
│  - Do the source Events exist in Event Store?        │
│  - Is the artifact accurately derived from events?   │
└──────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  Stage 4: Non-Contradiction                          │
│  - Does the artifact contradict accepted knowledge?  │
│  - Is the contradiction explicit (supersedes)?       │
│  - Does it contradict the Constitution?              │
└──────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  Stage 5: Privacy Compliance                         │
│  - Does the artifact expose evidence beyond org?     │
│  - Are entity identities properly anonymized?        │
│  - Does sharing comply with CPR-010?                 │
└──────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  Stage 6: Quality Checks                             │
│  - Is the artifact reproducible?                     │
│  - Is it complete?                                   │
│  - Is it current?                                    │
│  - Is it non-duplicative?                            │
│  - Is it deterministic?                              │
└──────────────────────────────────────────────────────┘
    │
    ▼
Validated (pass)  OR  Rejected (fail at any stage)
```

## Validation Rules Detail

### Stage 1: Schema Validation

| Rule | Check | Error Code |
|------|-------|------------|
| ACD-VAL-001 | Artifact has valid `type` (one of enumerated types) | `VAL.SCHEMA_001` |
| ACD-VAL-002 | Artifact has at least one `source_event_id` | `VAL.SCHEMA_002` |
| ACD-VAL-003 | Artifact `content` is valid JSON per type schema | `VAL.SCHEMA_003` |
| ACD-VAL-004 | Artifact `title` is present and ≤ 200 chars | `VAL.SCHEMA_004` |
| ACD-VAL-005 | Artifact `signature` is present | `VAL.SCHEMA_005` |
| ACD-VAL-006 | Artifact `version` matches SemVer pattern | `VAL.SCHEMA_006` |

### Stage 2: Constitutional Consistency

| Rule | Check | Error Code |
|------|-------|------------|
| ACD-VAL-007 | Artifact does not advocate constitutional violation | `VAL.CONST_001` |
| ACD-VAL-008 | Artifact does not override capability bounds (R1) | `VAL.CONST_002` |
| ACD-VAL-009 | Artifact respects entity autonomy level constraints | `VAL.CONST_003` |
| ACD-VAL-010 | Artifact does not suggest fail-open security patterns | `VAL.CONST_004` |
| ACD-VAL-011 | Artifact aligns with PHI-001 through PHI-010 | `VAL.CONST_005` |

### Stage 3: Evidence Provenance

| Rule | Check | Error Code |
|------|-------|------------|
| ACD-VAL-012 | All source Event IDs exist in Event Store | `VAL.PROV_001` |
| ACD-VAL-013 | Source Events are from the same or authorized org | `VAL.PROV_002` |
| ACD-VAL-014 | Artifact content_hash matches computed hash | `VAL.PROV_003` |
| ACD-VAL-015 | Source Events are accessible to Validator | `VAL.PROV_004` |

### Stage 4: Non-Contradiction

| Rule | Check | Error Code |
|------|-------|------------|
| ACD-VAL-016 | Artifact does not silently contradict accepted knowledge | `VAL.CONTR_001` |
| ACD-VAL-017 | If contradicting, artifact must explicitly supersede | `VAL.CONTR_002` |
| ACD-VAL-018 | Artifact does not contradict constitutional text | `VAL.CONTR_003` |
| ACD-VAL-019 | Contradiction weight (supports/contradicts) is computed | `VAL.CONTR_004` |

### Stage 5: Privacy Compliance

| Rule | Check | Error Code |
|------|-------|------------|
| ACD-VAL-020 | Artifact does not expose raw Event payloads | `VAL.PRIV_001` |
| ACD-VAL-021 | Entity identifiers are anonymized or authorized | `VAL.PRIV_002` |
| ACD-VAL-022 | Cross-org knowledge has federation policy check | `VAL.PRIV_003` |
| ACD-VAL-023 | PII is not present in artifact content | `VAL.PRIV_004` |

### Stage 6: Quality Checks

| Rule | Check | Error Code |
|------|-------|------------|
| ACD-VAL-024 | **Reproducible**: Knowledge can be reproduced from source events | `VAL.QUAL_001` |
| ACD-VAL-025 | **Complete**: Knowledge has sufficient context (title, description, content) | `VAL.QUAL_002` |
| ACD-VAL-026 | **Current**: Knowledge is not superseded by existing accepted artifact | `VAL.QUAL_003` |
| ACD-VAL-027 | **Non-duplicative**: No identical (by content_hash) accepted artifact exists | `VAL.QUAL_004` |
| ACD-VAL-028 | **Deterministic**: Operational knowledge produces deterministic outcomes (R9) | `VAL.QUAL_005` |

## Validation Result

The Validator produces a structured result for every artifact processed:

| Field | Type | Description |
|-------|------|-------------|
| `artifact_id` | UUID | Validated artifact ID |
| `passed` | Boolean | Overall validation result |
| `stages` | StageResult[] | Per-stage results |
| `score` | Float | Quality score (0.0–1.0) from stage 6 |
| `timestamp` | DateTime | Validation timestamp |
| `validator_id` | UUID | Validator entity ID |

### Stage Result

| Field | Type | Description |
|-------|------|-------------|
| `stage_number` | Integer | Stage (1–6) |
| `stage_name` | String | Human-readable name |
| `passed` | Boolean | Stage result |
| `errors` | ValidationError[] | Errors (if any) |
| `warnings` | String[] | Warnings (non-blocking) |

### ValidationError

| Field | Type | Description |
|-------|------|-------------|
| `code` | String | Unique error code (R12) |
| `message` | String | Human-readable description |
| `field` | String | Field that caused the error |
| `context` | JSON | Additional context for debugging |

## Validation Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Validator.ValidationStarted` | Validation begins for an artifact | artifact_id, pipeline_id |
| `Validator.StageCompleted` | A validation stage finishes | artifact_id, stage_number, passed |
| `Validator.StageFailed` | A validation stage rejects the artifact | artifact_id, stage_number, errors[] |
| `Validator.ValidationPassed` | All stages pass | artifact_id, score, validation_id |
| `Validator.ValidationFailed` | Any stage fails | artifact_id, failed_stage, errors[] |
| `Validator.QualityScoreComputed` | Quality score is calculated | artifact_id, score, quality_metrics |

## Cross-Cutting Concerns

### Security

The Validator operates within Security Council oversight. Constitutional consistency checks ensure no artifact can be used to circumvent constitutional constraints. Privacy checks ensure no evidence leakage (Physics/008-Security.md).

### Evidence

Every validation stage produces an Event. The full validation history of every artifact is reconstructable from Validator Events. This provides an audit trail for acceptance and rejection decisions.

### Lifecycle

Validation is a mandatory transition in the AKM lifecycle: Proposed → Validated. An artifact cannot proceed to verification without passing all validation stages. The Validator enforces this gate.

### Capability Bounds

The Validator itself is capability-bounded. It can read artifacts and Events but cannot write to the Registry or KMS. Its capabilities are limited to producing validation results (PHI-007, R1).

### Communication

The Validator receives proposed artifacts over ACF topic `academy.knowledge.proposed`. It publishes results to `academy.knowledge.validated` or `academy.knowledge.rejected`. The Verifier (006) subscribes to validated events.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Validator does validation — nothing else |
| R9 | Validation is deterministic: same artifact always produces same result |
| R10 | Pipeline is linear (6 stages, no branching) |
| R12 | Every error has a unique code (VAL.*) |
| R13 | Validator fails closed if dependency unavailable |
| R14 | Paved path: Stage 1 → 2 → 3 → 4 → 5 → 6 |
| R15 | New validation stages can be added without modifying existing ones |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/012-Experience.md | Validator checks knowledge against experience evidence |
| Governance/006-AKM.md | AKM validation rules are implemented by Validator |
| Foundations/001-AIOS-Philosophy.md | PHI-002, PHI-008 — evidence-driven validation |
| Foundations/003-Core-Principles.md | CPR-004, CPR-010 — evidence immutability, privacy |
| Foundations/002-Design-DNA.md | R1, R9, R10, R12, R13, R14, R15 |
| Foundations/006-Design-Rules.md | Design rules enforced by validation |
| 006-Knowledge-Verifier.md | Verifier is the next stage after Validator |
| 007-Knowledge-Review.md | Review (conditional) follows verification |
| 004-Knowledge-Registry.md | Registry consumes validation results |
| 016-Knowledge-API.md | Validation API endpoint |
