# AIOS Bible — Core
## Academy — 006: Knowledge Verifier

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-006 |
| Source Laws | Law 4 — Evidence, Law 9 — Deterministic |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge Verifier is the second gate in the Academy validation pipeline. While the Validator (005) checks constitutional and quality constraints, the Verifier confirms that knowledge is *accurately derived* from its source evidence. It is the operational embodiment of PHI-008 (Evidence Over Opinion): no knowledge is accepted unless it can be verified against the Evidence it claims to represent.

## Verification Methods

The Verifier uses four methods, applied in order:

| Method | Description | When Applied |
|--------|-------------|--------------|
| Evidence Replay | Re-run the analysis steps from source Events and confirm the same knowledge is produced | Always |
| Cross-Validation | Compare against existing accepted knowledge for consistency | Always (except novel domains) |
| Statistical Scoring | Compute confidence score based on evidence strength, volume, and consistency | Always |
| Adversarial Testing | Attempt to find counter-examples that disprove the knowledge | High-impact knowledge only |

### 1. Evidence Replay

The Verifier replays the analysis pipeline from the source Events to confirm the knowledge artifact is a correct derivation:

```
Source Events (from Event Store)
    │
    ▼
[Rerun Analysis Steps]
    │
    ▼
Produced Knowledge
    │
    ▼
[Compare with Proposed Artifact]
    │
    ├── Match → Evidence Replay Passed
    └── Mismatch → Evidence Replay Failed → Artifact Rejected
```

| Requirement | Detail |
|-------------|--------|
| Source Events | Must be accessible from Event Store |
| Analysis steps | Recorded in artifact metadata as `analysis_script` or `analysis_query` |
| Determinism | Analysis must be deterministic (R9) for replay to succeed |
| Match criteria | Content hash of replayed knowledge must match artifact content_hash |

### 2. Cross-Validation

Compare the proposed knowledge against existing accepted knowledge in the same domain:

| Check | Description | Threshold |
|-------|-------------|-----------|
| Consistency score | How well does the new knowledge align with existing? | ≥ 0.7 (configurable per type) |
| Novelty score | Does the knowledge add new information beyond existing? | ≥ 0.3 |
| Contradiction flag | Does the knowledge contradict accepted knowledge without explicit supersede? | Reject if unacknowledged |

Cross-validation uses the Knowledge Graph (003) to find related artifacts and compute support/contradiction edge weights.

### 3. Statistical Confidence Scoring

The Verifier computes a confidence score (0.0–1.0) for each artifact:

| Factor | Weight | Description |
|--------|--------|-------------|
| Evidence volume | 0.25 | Number of source Events supporting the knowledge (more = higher) |
| Evidence consistency | 0.25 | How consistent the source Events are with each other |
| Evidence recency | 0.15 | How recent the source Events are (newer = higher) |
| Replay fidelity | 0.20 | How closely the replayed knowledge matches the proposed |
| Cross-validation | 0.15 | Alignment with existing accepted knowledge |

**Score Interpretation**:

| Score Range | Meaning | Next Step |
|-------------|---------|-----------|
| 0.9–1.0 | Very high confidence | Proceed to acceptance (bypass review if type allows) |
| 0.7–0.9 | High confidence | Proceed to acceptance |
| 0.5–0.7 | Moderate confidence | Proceed to review (007) |
| 0.3–0.5 | Low confidence | Require human review |
| 0.0–0.3 | Very low confidence | Reject automatically |

Minimum confidence thresholds are configurable per knowledge type:

| Knowledge Type | Minimum Threshold | Review Threshold |
|----------------|------------------|-----------------|
| Operational | 0.5 | < 0.7 |
| Domain | 0.6 | < 0.8 |
| Constitutional | 0.8 | < 0.95 |
| Strategic | 0.6 | < 0.8 |
| Experimental | 0.2 | < 0.5 |

### 4. Adversarial Testing

For high-impact knowledge (constitutional interpretations, strategic decisions), the Verifier runs adversarial tests:

| Test | Description |
|------|-------------|
| Counter-example search | Query Event Store for Events that contradict the knowledge |
| Boundary testing | Test edge cases of the knowledge claim |
| Stress testing | Apply the knowledge to extreme scenarios and check for failure |
| Inverse verification | Verify that the absence of contrary evidence is not mistaken for confirmation |

## Verification Pipeline

```
Validated Artifact (from Validator)
    │
    ▼
┌──────────────────────────────────────────────┐
│  Stage 1: Evidence Replay                    │
│  ┌────────────────────────────────────────┐  │
│  │  Re-run analysis → Compare results    │  │
│  │  → Pass: continue → Fail: reject      │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Stage 2: Cross-Validation                   │
│  ┌────────────────────────────────────────┐  │
│  │  Query Knowledge Graph → Compute      │  │
│  │  consistency/novelty → Check flags    │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Stage 3: Statistical Scoring                │
│  ┌────────────────────────────────────────┐  │
│  │  Compute confidence (0.0–1.0) →       │  │
│  │  Determine next step based on score   │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Stage 4: Adversarial Testing (conditional)  │
│  ┌────────────────────────────────────────┐  │
│  │  If high-impact: run adversarial tests │  │
│  │  → Pass: publish results              │  │
│  │  → Fail: require human review         │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
    │
    ▼
Verified (pass)  OR  Review Required  OR  Rejected
```

## Verification Result

| Field | Type | Description |
|-------|------|-------------|
| `artifact_id` | UUID | Verified artifact ID |
| `passed` | Boolean | Overall verification result |
| `confidence_score` | Float | Computed confidence (0.0–1.0) |
| `replay_result` | Enum | Match, Mismatch, Inconclusive |
| `cross_validation_score` | Float | Cross-validation consistency score |
| `adversarial_results` | AdversarialResult[] | Results of adversarial tests (if run) |
| `recommendation` | Enum | Accept, Review, Reject |
| `timestamp` | DateTime | Verification timestamp |
| `verifier_id` | UUID | Verifier entity ID |

## Integration with DTS

The Verifier integrates with the Decision Trust System (DTS) for trust-weighted knowledge:

| DTS Integration | Purpose | Detail |
|-----------------|---------|--------|
| Confidence score input | DTS consumes verification confidence for trust calculations | DTS/004-Confidence.md |
| Trust-weighted knowledge | Knowledge is weighted by the trust in its source entity and verification | High-trust entities = faster acceptance |
| Reputation feedback | Verification results feed into entity reputation scores | DTS sim-engines |

## Verification Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Verifier.VerificationStarted` | Verification begins | artifact_id, methods_used |
| `Verifier.EvidenceReplayCompleted` | Evidence replay finishes | artifact_id, result, match_score |
| `Verifier.CrossValidationCompleted` | Cross-validation finishes | artifact_id, consistency_score, novelty_score |
| `Verifier.ConfidenceScoreComputed` | Confidence score calculated | artifact_id, score, score_factors |
| `Verifier.AdversarialTestCompleted` | Adversarial test finishes | artifact_id, test_type, result |
| `Verifier.VerificationPassed` | All verification passes | artifact_id, confidence, recommendation |
| `Verifier.VerificationFailed` | Verification fails | artifact_id, failed_method, errors |

## Cross-Cutting Concerns

### Security

The Verifier must have read access to Event Store and Knowledge Graph. It must NOT have write access to any store — it produces verification results only. Adversarial testing may generate queries against the Event Store but must not access entity-private data (CPR-010).

### Evidence

Every verification step produces an Event. The verification chain for every artifact is fully auditable. If an artifact is later found to be incorrect, the verification Events show exactly what checks were performed and why it passed.

### Lifecycle

Verification transitions the artifact from Validated to Verified state in the AKM lifecycle. If verification fails, the artifact is rejected and remains in Proposed or Validated (failed) state.

### Capability Bounds

The Verifier's capabilities are limited to producing verification results. It cannot accept or reject artifacts — that is the Registry's (004) role. It cannot modify artifacts in KMS.

### Communication

The Verifier subscribes to `academy.knowledge.validated` for input. It publishes results to `academy.knowledge.verified` and `academy.knowledge.verification_failed`. The Review (007) and Registry (004) subscribe to verification results.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Verifier does verification — nothing else |
| R9 | All verification methods are deterministic |
| R10 | Verification pipeline is linear (4 stages, sequential) |
| R13 | Verifier fails closed if Event Store or Knowledge Graph unavailable |
| R14 | Paved path: Replay → Cross-validate → Score → Adversarial (if needed) |
| R15 | New verification methods added without modifying existing stages |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Evidence replay consumes Events from Event Store |
| Physics/012-Experience.md | Verification ensures knowledge matches experience |
| Governance/006-AKM.md | AKM verification rules implemented by Verifier |
| Foundations/001-AIOS-Philosophy.md | PHI-008 — Evidence Over Opinion |
| Foundations/002-Design-DNA.md | R1, R9, R10, R13, R14, R15 |
| Core/DTS/004-Confidence.md | Confidence scoring integration |
| Core/DTS/003-Sim-Engines.md | DTS simulation for reputation feedback |
| 005-Knowledge-Validator.md | Precedes Verifier in pipeline |
| 007-Knowledge-Review.md | Follows Verifier in pipeline (conditional) |
| 003-Knowledge-Graph.md | Cross-validation uses Knowledge Graph |
| 016-Knowledge-API.md | Verification API endpoint |
