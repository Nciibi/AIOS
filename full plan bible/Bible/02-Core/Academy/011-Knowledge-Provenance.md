# AIOS Bible — Core
## Academy — 011: Knowledge Provenance

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-011 |
| Source Laws | Law 4 — Evidence |
| Source Physics | Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Knowledge Provenance provides immutable traceability from every knowledge artifact back to the source Events that produced it. It is the operational embodiment of PHI-008 (Evidence Over Opinion): every piece of knowledge in the Academy must have a verifiable chain of evidence supporting it. Anyone can verify that knowledge is accurately derived from Events.

## Constitutional Requirement

PHI-008 requires that all knowledge have verifiable provenance. The Provenance system enforces this by:

1. **Recording** — Every knowledge artifact stores its source Event IDs at creation
2. **Linking** — Each step in the knowledge production chain is recorded as a provenance link
3. **Verifying** — Anyone can verify the provenance chain at any time
4. **Immuting** — Provenance is immutable after acceptance; corrections create new versions

## Provenance Chain

The provenance chain traces a knowledge artifact back to its source:

```
Knowledge Artifact (v1.2.0)
    │
    │ derived_from
    ▼
Knowledge Artifact (v1.0.0)  ── if composed from existing knowledge
    │
    │ derived_from
    ▼
Analysis Step (pipeline execution)
    │
    │ produced_by
    ▼
Knowledge Pipeline (pipeline_id)
    │
    │ consumed
    ▼
Event (E-001) ── Entity (AG-042) ── Action
    │         produced_by
    │
    │ consumed
    ▼
Event (E-002) ── Entity (AG-055) ── Action
    │         produced_by
    │
    │ consumed
    ▼
Event (E-003) ── Entity (AG-042) ── Action
```

### Chain Links

Each link in the provenance chain is a record:

| Link Field | Type | Description |
|------------|------|-------------|
| `link_id` | UUID | Unique link identifier |
| `source_type` | Enum | Type of source (KnowledgeArtifact, Analysis, Event) |
| `source_id` | UUID | Source node identifier |
| `target_type` | Enum | Type of target (KnowledgeArtifact) |
| `target_id` | UUID | Target node identifier |
| `relationship` | Enum | `derived_from`, `produced_by`, `consumed`, `composed_of` |
| `timestamp` | DateTime | When the derivation occurred |
| `evidence` | JSON | Evidence supporting the link (analysis script, query) |
| `signature` | Signature | Cryptographic signature of the link |

### Chain Properties

| Property | Description |
|----------|-------------|
| **Immutable** | Once recorded, provenance links cannot be modified |
| **Auditable** | Full chain can be traversed from artifact to source Events |
| **Verifiable** | Each link includes evidence for the derivation step |
| **Complete** | Every artifact has at least one complete chain to source Events |
| **Acyclic** | Provenance is a directed acyclic graph (no circular derivations) |

## Provenance Storage

Provenance chains are stored in an append-only provenance log:

| Store | Content | Queryable By |
|-------|---------|--------------|
| Provenance Log (append-only) | All provenance links in order | artifact_id, event_id, timerange |
| Provenance Index (read-optimized) | Materialized chains for fast traversal | artifact_id (full chain lookup) |
| Provenance Cache (hot) | Recent/requested chains | artifact_id (LRU, 1000 entries) |

### Storage Format

Provenance links are stored as immutable records in the provenance log:

```
Provenance Log Entry:
{
    "link_id": "pl-001",
    "prev_hash": "abc123...",
    "source_type": "Event",
    "source_id": "E-001",
    "target_type": "KnowledgeArtifact",
    "target_id": "A-001",
    "relationship": "derived_from",
    "timestamp": "2026-07-09T12:00:00Z",
    "evidence": {
        "analysis_script_hash": "def456...",
        "pipeline_id": "PL-001"
    },
    "signature": "ghi789..."
}
```

## Provenance Operations

### getProvenance

Retrieve the full provenance chain for an artifact.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Knowledge artifact ID |
| `depth` | No | Maximum chain depth (default: full chain) |
| `include_events` | No | Include full source Event payloads (default: false) |
| `verify` | No | Verify chain integrity (default: true) |

**Response**:
```
{
    "artifact_id": "A-001",
    "chain": [
        { link_id, source_type, source_id, relationship, timestamp },
        ...
    ],
    "source_events": [
        { event_id, event_type, timestamp, summary }
    ],
    "verified": true,
    "verification_timestamp": "2026-07-09T12:00:00Z"
}
```

### verifyProvenance

Verify that a provenance chain is complete and correct.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Artifact to verify |
| `deep_verify` | No | If true, re-run evidence replay (default: false) |

**Response**:
```
{
    "artifact_id": "A-001",
    "chain_complete": true,
    "chain_integrity": true,
    "all_events_exist": true,
    "evidence_replay_match": true,
    "verified": true,
    "details": { ... }
}
```

### getProvenanceByEvent

Find all artifacts derived from a specific Event.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `event_id` | Yes | Source Event ID |
| `include_indirect` | No | Include artifacts derived indirectly (default: true) |

**Response**: `{ event_id, direct_artifacts: [], indirect_artifacts: [], total_count }`

### compareProvenance

Compare provenance chains of two artifacts to find shared source Events.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id_a` | Yes | First artifact |
| `artifact_id_b` | Yes | Second artifact |

**Response**: `{ shared_events: [], a_only: [], b_only: [], overlap_score: 0.0–1.0 }`

## Provenance Verification

Anyone can verify that knowledge is accurately derived from Events. The verification process:

```
1. Fetch provenance chain for artifact
2. For each link, verify:
   a. Source exists (Event in Event Store, analysis step recorded)
   b. Relationship is valid (derived_from, produced_by, etc.)
   c. Evidence for the link is available
3. Verify chain integrity:
   a. Hash chain is intact (each link references prev_hash)
   b. No missing links (chain is complete from artifact to Events)
4. Optionally: re-run evidence replay to confirm derivation accuracy
5. Return verification result
```

### Verification Levels

| Level | Checks | Cost |
|-------|--------|------|
| **Light** | Chain completeness, link signatures | Low |
| **Standard** | Light + source Event existence check | Medium |
| **Deep** | Standard + evidence replay verification | High |

## Provenance Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Provenance.LinkCreated` | New provenance link is recorded | link_id, source_id, target_id, relationship |
| `Provenance.ChainVerified` | Provenance chain is verified | artifact_id, verification_level, result |
| `Provenance.ChainVerificationFailed` | Chain verification fails | artifact_id, failed_link, reason |
| `Provenance.ProvenanceQueried` | Provenance chain is retrieved | artifact_id, depth, result_count |
| `Provenance.EventTraced` | Artifacts derived from an Event are listed | event_id, artifact_count |

## Cross-Cutting Concerns

### Security

Provenance links are cryptographically signed. Tampering with provenance is detectable via hash chain integrity checks. Access to provenance data is authorized — an entity can only see provenance for artifacts it has `knowledge.query` capability for.

### Evidence

The provenance chain is itself evidence. Every provenance link is an Event in the provenance log. The provenance log is immutable — links cannot be modified or deleted (CPR-004). This ensures the provenance of provenance is also traceable.

### Lifecycle

Provenance is recorded at artifact creation and updated with new versions. When an artifact is deprecated, its provenance chain remains intact (deprecated knowledge still has verifiable provenance). Archived artifacts retain their provenance for audit purposes.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| Get provenance | `knowledge.query` |
| Verify provenance | `knowledge.query` |
| Deep verify | `knowledge.query.verify` (high resource cost) |
| Trace by Event | `knowledge.query` |

### Communication

Provenance operations are accessed through ACF. The Provenance service reads from the Event Store (for source Event verification) and KMS (for artifact data). It publishes provenance events for audit and analytics consumption.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Provenance does tracing and verification — does not store artifacts |
| R3 | Provenance is recorded once in the provenance log (single authoritative source) |
| R4 | Provenance chains are built by the knowledge pipeline, not constructed ad hoc |
| R9 | Provenance verification produces deterministic results |
| R12 | Every verification error has a unique error code |
| R13 | Provenance fails closed if Event Store or KMS is unavailable |
| R14 | Paved path: artifact → getProvenance → verify → result |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Events are the source of all provenance chains |
| Governance/006-AKM.md | AKM requires provenance for all knowledge |
| Foundations/001-AIOS-Philosophy.md | PHI-008 — Evidence Over Opinion (constitutional basis) |
| Foundations/003-Core-Principles.md | CPR-004 — Evidence Is Immutable |
| Foundations/002-Design-DNA.md | R1, R3, R4, R9, R12, R13, R14 |
| 002-KMS.md | KMS stores artifacts that have provenance chains |
| 003-Knowledge-Graph.md | Knowledge Graph provides traversal for provenance |
| 005-Knowledge-Validator.md | Stage 3 validates provenance at proposal time |
| 006-Knowledge-Verifier.md | Evidence replay verifies provenance accuracy |
| 016-Knowledge-API.md | Provenance API endpoints |
