# AIOS Bible — Reference
## 002 — ADG Index

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Reference |
| Document ID | REF-ADG-002 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The ADG Index catalogs all Architectural Decision Gateway decisions made during the evolution of AIOS. Every ADG entry represents a reviewed and approved architectural decision that affects module boundaries, interface contracts, service dependencies, or structural patterns. This index provides a single point of reference for the current architectural state.

## ADG Status Key

| Status | Meaning |
|--------|---------|
| Proposed | ADG drafted but not yet reviewed |
| Approved | ADG reviewed and accepted |
| Recorded | ADG stored in CKR |
| Deprecated | ADG no longer recommended for new work |
| Superseded | ADG replaced by a newer ADG |
| RFC Pending | ADG approved; RFC in progress |

## ADG Index

### ADG-001: ACF Message Routing Topology

| Property | Value |
|----------|-------|
| Date | 2026-01-15 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 3 — Law of Communication |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: ACF uses a topic-based publish/subscribe model with hierarchical topic namespaces. Messages are routed based on topic subscriptions. Topics follow the pattern `aios/<domain>/<entity_type>/<entity_id>/<action>`.

**Rationale**: Hierarchical topics provide natural access control boundaries, enable fine-grained subscriptions, and support wildcard patterns for monitoring and audit. The topic structure mirrors the organizational hierarchy.

**Impact**: All entities must subscribe to topics following this naming convention. Existing ad-hoc topic structures must be migrated.

**Design DNA Compliance**: R1 (ACF handles routing only), R10 (topic hierarchy is the simplest routing model), R14 (topic naming convention is the paved path).

---

### ADG-002: Event Schema Versioning Strategy

| Property | Value |
|----------|-------|
| Date | 2026-01-22 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Event schemas are versioned using semantic versioning (MAJOR.MINOR.PATCH). Backward-compatible changes (new optional fields) increment MINOR. Breaking changes increment MAJOR. The Event Store supports multiple schema versions simultaneously.

**Rationale**: Semantic versioning provides clear compatibility guarantees. Supporting multiple schema versions allows gradual migration without system-wide downtime. Consumers declare which schema versions they support.

**Impact**: Every Event type must declare its schema version. Event consumers must handle at least one version. Schema registries must be maintained.

**Design DNA Compliance**: R3 (schema defined once in registry), R13 (backward compatibility ensures consumers are not broken), R15 (new fields can be added without breaking existing consumers).

---

### ADG-003: Worker Isolation Model

| Property | Value |
|----------|-------|
| Date | 2026-02-05 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Workers run in isolated sandboxes (container-based). Each Worker has its own filesystem, network namespace, and process space. Workers communicate only through ACF. No Worker may access another Worker's sandbox.

**Rationale**: Container isolation provides strong security boundaries, resource accounting, and clean teardown. It satisfies Law 7 (Capability Bounds) by enforcing resource limits at the OS level. ACF-only communication satisfies Law 3.

**Impact**: All Runtimes must support container-based isolation. Resource limits must be mapped to container cgroup settings. Evidence collection must work across container boundaries.

**Design DNA Compliance**: R1 (isolation is a single concern), R13 (failure in one Worker does not affect others), R14 (container sandbox is the paved path for Worker execution).

---

### ADG-004: Knowledge Storage Architecture

| Property | Value |
|----------|-------|
| Date | 2026-02-12 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Knowledge is stored in a structured knowledge graph (not a document store). Nodes represent entities, concepts, and patterns. Edges represent relationships. Each knowledge item has a confidence score, source evidence chain, and expiration.

**Rationale**: A knowledge graph captures relationships between knowledge items that a flat document store cannot. Confidence scores enable the Academy to prioritize reliable knowledge. Source evidence chains provide traceability to original Events.

**Impact**: The KMS must support graph queries. Knowledge items must include provenance metadata. Confidence scoring requires the KEE evaluation pipeline.

**Design DNA Compliance**: R1 (KMS handles knowledge storage only), R3 (knowledge stored once, referenced by edges), R10 (graph model for relational knowledge is simpler than relational DB with join tables).

---

### ADG-005: Resource Allocation Model

| Property | Value |
|----------|-------|
| Date | 2026-02-20 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 7 — Law of Capability Bounds, Law 10 — Law of Tenure |
| Source Physics | Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Resources are allocated through a two-phase model: Reservation (budget allocation at Organization/Mission level) followed by Assignment (concrete resource binding at Worker execution time). The ROS manages both phases.

**Rationale**: Two-phase allocation separates strategic resource planning (budgeting) from operational resource binding (scheduling). Organizations can plan resource needs without knowing exact execution details. Workers receive resources at execution time based on availability.

**Impact**: Every Mission must have a resource budget. Workers declare resource requirements in their capability bounds. ROS tracks allocation and usage for accounting.

**Design DNA Compliance**: R1 (reservation and assignment are separate concerns), R4 (allocation is built by ROS, consumed by Workers), R13 (assignment fails gracefully if resources unavailable).

---

### ADG-006: Cross-Instance Communication Security Model

| Property | Value |
|----------|-------|
| Date | 2026-03-01 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 3 — Law of Communication, Law 5 — Law of Identity |
| Source Physics | Physics/009-Interaction.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Cross-instance communication uses mutual TLS (mTLS) with instance-level certificates issued by each instance's IRS. Messages are encrypted end-to-end. Remote identities are verified through a cross-instance identity resolution protocol (IXP).

**Rationale**: mTLS provides mutual authentication and encryption. Instance-level certificates scale better than per-entity certificates across instances. IXP resolves remote identities without requiring a shared identity registry.

**Impact**: Every instance must have a certificate authority. IXP must be implemented in all instances that participate in federation. Cross-instance communication is restricted to L2+ entities.

**Design DNA Compliance**: R1 (IXP handles identity resolution only), R13 (cross-instance communication fails gracefully if remote instance unavailable), R15 (protocol can be extended for new federation patterns).

---

### ADG-007: SDK Architecture and Versioning

| Property | Value |
|----------|-------|
| Date | 2026-03-10 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 3 — Law of Communication |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Four SDKs (Runtime, Audit, Knowledge, Provider) are maintained with independent versioning. Each SDK is a library that encapsulates ACF communication, identity verification, and evidence recording. SDKs follow semantic versioning.

**Rationale**: Independent SDKs allow each integration point to evolve at its own pace. Encapsulating ACF communication ensures Law 3 compliance. Semantic versioning provides clear compatibility guarantees for SDK consumers.

**Impact**: All Runtimes must link against the Runtime SDK. All Providers must use the Provider SDK. SDK version must be declared in entity metadata.

**Design DNA Compliance**: R3 (SDK encapsulates platform integration logic), R6 (SDK provides interfaces, not concrete implementations), R14 (SDK is the paved path for platform integration).

---

### ADG-008: Academy Learning Pipeline Stages

| Property | Value |
|----------|-------|
| Date | 2026-03-18 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: The Academy learning pipeline has five stages: Collection (gather Events), Filtering (remove noise), Analysis (extract patterns), Validation (verify against known knowledge), and Storage (persist to knowledge graph). Each stage is a separate module.

**Rationale**: Separating the pipeline into stages satisfies R1 (Modulsingularity). Each stage can be improved independently. Stages can be parallelized for performance. The pipeline is data-driven — no stage modifies the original Events.

**Impact**: Each stage must produce evidence of its operation. Pipeline throughput must keep pace with Event production rate. Staging failures must not cause data loss.

**Design DNA Compliance**: R1 (each stage does one thing), R2 (pipeline is acyclic), R7 (each stage must have tests), R8 (pipeline must process Events faster than they are produced).

---

### ADG-009: Organization Hierarchy Depth

| Property | Value |
|----------|-------|
| Date | 2026-03-25 |
| Status | Recorded |
| Author | Architecture Review Board |
| Source Laws | Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/003-Organizations.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Organization hierarchy is limited to four levels: Root Organization (platform level), Domain Organizations (functional areas), Departments (sub-domains), and Teams (operational units). No hierarchy may exceed four levels.

**Rationale**: Limiting hierarchy depth prevents excessive nesting that would complicate governance, slow decision-making, and obscure accountability. Four levels provide sufficient flexibility for organizational structure while maintaining tractable governance.

**Impact**: Any proposed Organization deeper than four levels requires an ADG exception. Existing deep hierarchies must be flattened or restructured. Governance policies apply uniformly at all levels.

**Design DNA Compliance**: R1 (hierarchy management is a single concern), R10 (four levels is the simplest structure that meets organizational needs), R15 (additional levels require ADG exception, not code change).

---

### ADG-010: Event Retention and Archival Policy

| Property | Value |
|----------|-------|
| Date | 2026-04-02 |
| Status | Deprecated |
| Author | Architecture Review Board |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | ADG-012 |

**Decision**: Events are retained in the primary Event Store for 90 days, then archived to cold storage for 7 years, then deleted. Archived Events are compressed and stored in a separate encrypted store.

**Rationale**: 90 days of hot storage supports active operations and recent audit. 7 years of cold storage satisfies regulatory requirements. Deletion after 7 years limits data liability.

**Design DNA Compliance**: R10 (simple retention policy is easier to implement and audit).

**Note**: Superseded by ADG-012 (Extended Retention Model) which introduces tiered retention based on Event classification.

---

### ADG-011: Capability Certification Process

| Property | Value |
|----------|-------|
| Date | 2026-04-10 |
| Status | Approved |
| Author | Architecture Review Board |
| Source Laws | Law 7 — Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Capability certification follows a three-stage process: Application (Worker declares desired capabilities), Verification (Security Council validates against template), and Granting (CCA issues capability certificate). Capabilities are time-limited and must be renewed.

**Rationale**: Three-stage certification ensures capabilities are properly evidenced before granting. Time-limited capabilities force periodic review and prevent permanent privilege accumulation. CCA maintains the capability registry.

**Impact**: Every capability requires a certificate. Certificates expire and must be renewed. Working without a valid certificate is a security violation.

**Design DNA Compliance**: R1 (certification is a single concern), R4 (certificates are built by CCA, consumed by Security Kernel), R14 (three-stage process is the paved path for capability assignment).

---

### ADG-012: Extended Event Retention Model

| Property | Value |
|----------|-------|
| Date | 2026-04-15 |
| Status | Approved |
| Author | Architecture Review Board |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | ADG-010 |
| Superseded By | Nothing |

**Decision**: Event retention is tiered by Event classification: Critical Events (retained indefinitely in primary store), Operational Events (90 days hot, 7 years cold), Debug Events (30 days hot, 1 year cold), Transient Events (7 days, no archival). Classification is set by the producing entity and verified by EVS.

**Rationale**: Tiered retention balances storage efficiency with regulatory requirements. Critical Events (constitutional amendments, security incidents, capability changes) must be retained indefinitely. Transient Events (heartbeats, status checks) can be discarded quickly.

**Impact**: Every Event type must have a retention classification. EVS must enforce retention policies. Archival and deletion must be automated and evidenced.

**Design DNA Compliance**: R10 (tiered classification is simpler than uniform retention for all Event types), R13 (classification errors default to higher retention).

---

### ADG-013: Plugin System Architecture

| Property | Value |
|----------|-------|
| Date | 2026-04-20 |
| Status | RFC Pending |
| Author | Architecture Review Board |
| Source Laws | Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Decision**: Plugins are sandboxed modules that register capabilities through the Plugin SDK. Each plugin declares its dependencies, capabilities, and resource requirements. Plugins communicate through ACF and are subject to Security Kernel verification.

**Rationale**: Sandboxed plugins allow extension without compromising core system security. Declared capabilities enable the Security Kernel to verify plugin actions. ACF communication ensures observability.

**Impact**: Plugin development requires Plugin SDK. Plugin installation requires Security Council approval. Plugin updates require re-certification. A plugin marketplace requires ecosystem infrastructure.

**Design DNA Compliance**: R1 (plugin is an extension, not a core module), R13 (plugin failure must not affect core system), R15 (plugins extend the system without modifying it).

## Cross-Cutting Concerns

### Security
Every ADG entry is reviewed by the Architecture Review Board for security impact. ADGs affecting the Security Kernel, identity, or capability boundaries require additional Security Council review. ADG-006 (Cross-Instance Security) and ADG-003 (Worker Isolation) are security-critical.

### Evidence
ADG decisions are recorded in CKR with full context, rationale, and alternatives. Status changes are evidenced. Superseded ADGs remain indexed with a reference to the superseding entry. The ADG index itself is versioned.

### Lifecycle
ADGs follow the governance lifecycle defined in `01-Governance/005-ADG.md`. Each ADG progresses from Proposed → Approved → Recorded. Deprecated and Superseded entries remain in the index for historical reference.

### Capability Bounds
ADGs may define or refine capability boundaries for entities, modules, or protocols. Capability-bound ADGs (ADG-003, ADG-005, ADG-011) must declare the scope, limits, and verification mechanism.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Each ADG addresses exactly one architectural concern. |
| R10 | ADGs must demonstrate that the chosen approach is the simplest valid solution. |
| R12 | Every ADG includes an Impact section documenting consequences. |
| R14 | ADGs define the paved path for architectural decisions. |

### Interoperability
ADGs that define interfaces, protocols, or data formats must include interoperability requirements. Cross-instance ADGs (ADG-006) must specify version negotiation and backward compatibility.

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Decision-Log.md | ADR log — approved ADGs that produce ADRs are cross-referenced |
| 01-Governance/005-ADG.md | ADG process — this index catalogs all ADG decisions |
| 01-Governance/004-CKR.md | CKR stores the authoritative record of each ADG |
| 00-Foundations/002-Design-DNA.md | Design DNA — every ADG must comply with R1–R15 |
| Physics/011-Design-DNA.md | Physics source of Design DNA rules |
| 10-Research/002-Ecosystem.md | Plugin research — ADG-013 proposes the plugin architecture |
