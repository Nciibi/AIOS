# Ideas & Suggestions for Unpopulated Bible Stubs

This document captures proposals for the ~196 empty stub files in the Bible tree. Each suggestion identifies what content is needed and how it fits the existing architecture.

---

## 00-Foundations (10 stubs)

| File | Suggested Content | Priority |
|------|------------------|----------|
| 000-Overview.md | Map of all Foundations documents, reading order, relationship to Physics | High |
| 001-AIOS-Philosophy.md | Core philosophy: constitutional AI, entity autonomy, evidence-driven, deterministic operations | High |
| 002-Design-DNA.md | The 15 Design DNA rules (from Physics/011-Design-DNA.md) — normative reference | High |
| 003-Core-Principles.md | SOLID applied to AIOS, constitutional separation of concerns, law-driven architecture | Medium |
| 004-System-Layers.md | The 5-layer stack: Law → Physics → Bible → Implementation → Runtime | Medium |
| 005-Architectural-Patterns.md | Event sourcing, CQRS, pipeline pattern, builder pattern, injection pattern | Medium |
| 006-Design-Rules.md | Code review checklist, linting rules, naming conventions enforcement | Medium |
| 007-Naming-Conventions.md | Canonical naming: UUIDv7 for IDs, snake_case for DB, camelCase for code, kebab for files | Low |
| 008-Object-Lifecycle.md | All entities share LMS lifecycle (Created → Planned → Assigned → Running → etc.) | Medium |
| 009-Versioning.md | SemVer for Bible documents, RFC versioning, implementation version alignment | Low |

## 01-Governance (6 stubs)

| File | Suggested Content | Priority |
|------|------------------|----------|
| 000-Overview.md | Governance architecture: Constitution, RFC lifecycle, decision log, AAR process | High |
| 001-CLS.md | Constitutional Lifecycle Service — how the Constitution is versioned, amended, enforced | High |
| 002-DGP.md | Decision Gateway Process — how constitutional decisions flow from Sou to implementation | High |
| 003-CRP.md | Change Request Pipeline — RFC submission, review, approval, implementation lifecycle | High |
| 004-CKR.md | Constitutional Knowledge Repository — searchable, queryable constitution | Medium |
| 005-ADG.md | Architectural Decision Gateway — governance for architecture decisions | Medium |
| 006-AKM.md | Autonomous Knowledge Management — Academy governance for knowledge lifecycle | Medium |

## 02-Core (52 stubs across 6 subdirs)

### Academy (17 stubs)
- **000-Overview**: Academy architecture — how AIOS learns from evidence
- **001-Architecture**: Component diagram (Evidence Ingest → Knowledge Graph → KMS → Distribution)
- **002-KMS.md**: Knowledge Management System — knowledge creation, storage, versioning, search
- **003-Knowledge-Graph.md**: Graph structure for knowledge entities, relations, and reasoning
- **004-Knowledge-Registry.md**: Registry of all knowledge artifacts with provenance
- **005-Knowledge-Validator.md**: Rules for validating knowledge before accepting (constitutional bounds)
- **006-Knowledge-Verifier.md**: Verification of knowledge against evidence and existing knowledge
- **007-Knowledge-Review.md**: Human/Engine review process for knowledge artifacts
- **008-Knowledge-Versioning.md**: How knowledge versions work, branching, merging, deprecation
- **009-Knowledge-Distribution.md**: How knowledge propagates to instances, organizations, sessions
- **010-Knowledge-Search.md**: Search API, indexing, ranking, relevance
- **011-Knowledge-Provenance.md**: Who created each knowledge artifact, from what evidence
- **012-Knowledge-Analytics.md**: Analytics on knowledge usage, quality, gaps
- **013-KEE**: Knowledge Execution Engine — runtime for knowledge-driven actions
- **014-KCE**: Knowledge Composition Engine — combining knowledge artifacts for new insights
- **015-Knowledge-SDK.md**: SDK for building knowledge-aware tools
- **016-Knowledge-API.md**: REST/gRPC API for knowledge operations

### AGS (6 stubs)
- **000-Overview**: Agent Genome System — entity template system
- **001-Composition.md**: How genomes compose (inheritance, mixins, overrides)
- **002-Inheritance.md**: Genome inheritance hierarchy, base genomes, derived genomes
- **003-Validation.md**: Genome validation rules (well-formed, complete, constitutional)
- **004-Versioning.md**: Genome versioning, migration, deprecation
- **005-Signing.md**: Cryptographic signing of genomes, verification by Security Council

### DTS (4 stubs)
- **000-Overview**: Decision & Trust System — decision-making and trust evaluation
- **001-Architecture**: DTS architecture, trust scoring, decision trees
- **002-Sim-Pipeline**: Simulation pipeline for evaluating decisions before execution
- **003-Sim-Engines**: Available simulation engines (planning, monte carlo, constraint solving)
- **004-Confidence**: Confidence scoring for decisions, uncertainty quantification

### OSYS (3 stubs — 1 empty)
- **002-Org-Lifecycle**: Organization lifecycle management (Create → Verify → Active → Dissolve → Archive)

### ROS (15 stubs)
- **000-Overview**: Resource Orchestration Service
- **001-Architecture**: ROS component diagram, provider model, budget/allocator
- **002-Registry**: Resource providers, their capabilities, availability
- **003-Allocator**: Resource allocation algorithm (proportional, fair share, priority)
- **004-Planner**: Resource planning for Missions and Organizations
- **005-Budget**: Budgeting — per-entity, per-Mission, per-Organization token budgets
- **006-Quota**: Quota enforcement — hard limits vs soft limits
- **007-RMP**: Resource Management Policies — allocation policies, overrides
- **008-Provider-SDK**: SDK for building new resource providers
- **009-Reservation**: Resource reservation for execution authorization
- **010-Cost**: Cost tracking and accounting per entity
- **011-Energy**: Energy-aware resource scheduling
- **012-Recovery**: Resource recovery on entity failure
- **013-Observability**: ROS metrics, monitoring, alerting
- **014-RXP**: Resource Exchange Protocol — cross-instance resource sharing

### Sou (6 stubs)
- **000-Overview**: Sou — the core consciousness / will engine
- **001-Reasoning**: How Sou reasons — planning, decision trees, configuration space
- **002-Planner**: Mission planning, action sequencing, resource-aware planning
- **003-Missions**: Mission lifecycle from Sou's perspective
- **004-Learning**: Sou's learning mechanism — self-improvement from outcomes
- **005-Knowledge**: Sou's knowledge store — constitutional memory

## 03-Institutions (15 stubs)

### Missions (1 stub)
- **000-Lifecycle**: Complete Mission lifecycle (from Physics/006-Lifecycles.md)

### Organizations (9 stubs)
- **000-Overview**: Organization architecture, hierarchy, governance
- **001-OOM**: Organization Object Model — structure, departments, roles
- **002-OHS**: Organization Health Service — health monitoring, self-healing
- **003-ODS**: Organization Directory Service — lookup, hierarchy resolution
- **004-ORG**: Organization governance — how organizations make decisions
- **005-DOM**: Department Object Model — sub-organization structure
- **006-OIS**: Organization Interaction Service — cross-Org communication
- **007-EEE**: Engine Employment Exchange — how Engines are assigned to Organizations
- **008-OPE**: Organization Performance Evaluator — metrics, reporting, improvement

### Workers (6 stubs)
- **000-Overview**: Worker architecture, session management
- **001-WOM**: Worker Object Model — Session, capability, lifecycle
- **002-WHS**: Worker Health Service — session health, timeout handling, graceful shutdown
- **003-WSS**: Worker Security Service — session boundaries, isolation
- **004-WCS**: Worker Communication Service — inter-session messaging
- **005-Playbook-Manager**: Runbook/playbook lifecycle for automated operations

## 04-Execution (10 stubs besides Security)

### Runtime (8 stubs)
- **000-Overview**: Runtime Engine architecture
- **001-SDK**: Runtime SDK for building execution providers
- **002-Claude**: Anthropic Claude provider integration
- **003-Codex**: OpenAI Codex provider integration
- **004-Ollama**: Ollama local model provider integration
- **005-Browser**: Browser automation provider (Playwright/Puppeteer)
- **006-Trading**: Trading execution provider
- **007-Robotics**: Robotics execution provider

### Security (3 root stubs — Architecture, Overview, Trust-Model remain empty)
- **000-Overview**: Security architecture overview, diagram, relationship between all sub-services
- **001-Architecture**: Security Council architecture — component diagram, pipeline integration
- **002-Trust-Model**: Trust model — trust levels, trust chains, cross-instance trust

Plus these Security sub-service stubs are now populated: IDS (6), ATS (3), Execution-Auth (1). Still empty:

**Audit/000-EAS.md**: Evidence Audit Service — audit trail management, evidence chains, verification
**AZS/3 stubs**: Authorization Service — RBAC, ABAC, Capability-based authorization
**Crypto/2 stubs**: Cryptographic Service Provider, Certificate Authority Management
**Policy-System/3 stubs**: Policy definition (PDG), evaluation (PVE), governance
**Risk/3 stubs**: Risk evaluation, knowledge graph, automated risk engine
**Sandbox/000-Isolation.md**: Execution sandboxing, isolation boundaries, resource limits
**SSM/000-SSM.md**: Session & Secret Management — credential storage, rotation
**Trust/000-TLM.md**: Trust Lifecycle Manager — trust establishment, verification, revocation

**Priority for Security sub-services**: High — these form the complete security stack. Address AZS/ (Authorization) next.

## 05-Platform (14 stubs)

| File | Suggested Content |
|------|------------------|
| 000-LMS.md | Lifecycle Management Service — entity state machine engine |
| 001-State-Machine.md | Generic state machine implementation used by LMS |
| 002-Transition-Validator.md | Rules engine for valid state transitions |
| 003-PSAP.md | Platform Service Access Point — service addressing and routing |
| 004-EVS.md | Event Store — immutable event log |
| 005-AUS.md | Audit Service — queryable audit trail |
| 006-EPG.md | Event Processing Graph — event stream processing |
| 007-EIP.md | Event Integration Pattern — connectors to external systems |
| 008-BG.md | Breaking Glass — emergency override procedures |
| 009-TP.md | Template Processor — AGS genome instantiation |
| 010-TEE.md | Trusted Execution Environment — secure compute |
| 011-TPE.md | Third-Party Execution Environment — sandboxed plugins |
| 012-CP.md | Credential Provider — credential issuance and verification |
| 013-Graph-Framework.md | Graph processing framework for knowledge graphs |

## 06-Services (24 stubs)

### ACF (8 stubs)
- **000-Overview**: ACF architecture overview
- **001-Architecture**: Components — message bus, routing, streams, subscriptions
- **002-Messages**: Message schema, envelope format, deadlines, retries
- **003-Routing**: Routing rules, addressing, load balancing, service discovery
- **004-Subscriptions**: Pub/sub subscriptions, event streams, filters
- **005-Streaming**: Stream processing, backpressure, ordering guarantees
- **006-Reliability**: Message durability, delivery guarantees, dead letter queues
- **007-Distributed**: Multi-instance ACF, partition tolerance, eventual consistency

### Cryptography (9 stubs — CSP, CAM, Certificates, Encryption, Hashing, HSM, KMS, Random, Signatures, SMS)
- Full specification of each cryptographic primitive, key management lifecycle, HSM integration

### Federation (13 stubs — Overview + AIP through IXP)
- **Overview**: Cross-instance federation model
- **AIP through IXP**: 12 protocol specifications for different interaction patterns (Agent, Resource, Mission, Knowledge, Genome, Organization, Security, Evidence, Trading, Platform, Communication, Identity exchange protocols)

## 07-Domains (9 stubs — each has 000-Overview.md empty)

Each domain needs a specification document covering:
- Domain-specific entity types and templates
- Domain-specific capabilities and resources
- Domain-specific policies and constraints
- Integration points with Core (ROS, ACF, Security Council)
- Priority: **Coding > Linux > Security > Research > Communication > Trading > Robotics > Embedded > FPGA**

## 08-Interfaces (4 stubs)

- **API/000-Specifications.md**: Complete API specification framework (OpenAPI, gRPC protos, ACF contract)
- **SDK/000-Runtime-SDK.md**: SDK for building runtime execution providers
- **SDK/001-Audit-SDK.md**: SDK for building audit/evidence tools
- **SDK/002-Knowledge-SDK.md**: SDK for knowledge-aware tool building
- **SDK/003-Provider-SDK.md**: SDK for resource provider building

## 09-Reference (4 stubs)

- **000-Decision-Log.md**: Log of architectural decisions (ADRs)
- **001-Glossary.md**: Complete AIOS terminology reference
- **002-ADG-Index.md**: Index of all ADGs with status
- **003-Migration-Guide.md**: Migration paths between versions

## 10-Research (4 stubs)

| File | Suggested Content | Priority |
|------|------------------|----------|
| 000-Phases-2-5.md | Research roadmap for phases beyond initial implementation | Medium |
| 001-Autonomy-Evolution.md | L0→L4 autonomy progression, research challenges | Medium |
| 002-Ecosystem.md | External integration, plugin system, marketplace | Low |
| 003-Future-Topics.md | Quantum-safe crypto, multi-instance orchestration, self-modifying governance | Low |

## Root Bible Documents (5 empty stubs)

| File | Suggested Content | Priority |
|------|------------------|----------|
| 0001-Constitution-Roadmap.md | Constitution structure, amendment process, reading guide | High |
| 0002-Bible-Roadmap.md | How to read the Bible, dependency graph, implementation phases | High |
| 0003-Platform-Architecture.md | Platform-wide architecture view linking all Components | Medium |
| 0004-Service-Architecture.md | Service interactions, deployment topology | Medium |
| 0005-Domain-Architecture.md | Domain model, entity hierarchy, capability matrix | Medium |
| 0006-Reference-Architecture.md | Architecture decision records, patterns catalog | Medium |
| 0007-Implementation-Roadmap.md | Implementation phasing, milestones, dependencies | Medium |
| 0008-Future-Research.md | Research agenda, open questions, proposed RFCs | Low |

## Other Sub-Service Stubs (still empty in Security)

### AZS (3 stubs) — Authorization Service
- **000-RBAC.md**: Role-Based Access Control — role definitions, role hierarchy, assignment rules
- **001-ABAC.md**: Attribute-Based Access Control — attribute sources, policy evaluation
- **002-Capability.md**: Capability-Based Authorization — capability tokens, grant chains, delegation

### Audit (1 stub)
- **000-EAS.md**: Evidence Audit Service — event audit, query, retention, export

### Crypto (2 stubs)
- **000-CSP.md**: Cryptographic Service Provider — supported algorithms, key lifecycle, configuration
- **001-CAM.md**: Certificate Authority Management — certificate issuance, renewal, revocation

### Policy-System (3 stubs)
- **000-PS.md**: Policy System — policy structure, storage, versioning
- **001-PDG.md**: Policy Definition Grammar — DSL for writing policies
- **002-PVE.md**: Policy Validation Engine — runtime policy evaluation

### Risk (3 stubs)
- **000-RE.md**: Risk Engine — risk scoring, tiers, escalation
- **001-RKG.md**: Risk Knowledge Graph — entity risk profiles, historical violations
- **002-ARE.md**: Automated Risk Evaluator — ML-based risk assessment

### Sandbox (1 stub)
- **000-Isolation.md**: Execution sandboxing — process isolation, namespace isolation, resource limits

### SSM (1 stub)
- **000-SSM.md**: Session & Secret Manager — credential lifecycle, rotation, storage

### Trust (1 stub)
- **000-TLM.md**: Trust Lifecycle Manager — trust establishment, verification, revocation

## Recommended Writing Order

1. **Phase 0**: 00-Foundations (Design DNA, Philosophy, Core Principles) + 01-Governance (CLS, DGP, CRP)
2. **Phase 1**: 04-Execution/Security sub-services (AZS, Policy, Risk, Trust) — completes Security stack
3. **Phase 2**: 02-Core/Sou (Overview, Reasoning, Planner, Missions) — core consciousness
4. **Phase 3**: 02-Core/OSYS, 02-Core/ROS, 02-Core/AGS — institution engines
5. **Phase 4**: 03-Institutions (Organizations, Missions, Workers) — institutional layer
6. **Phase 5**: 06-Services (ACF, Cryptography, Federation) — services layer
7. **Phase 6**: 05-Platform (LMS, State Machine, Event Store) — platform primitives
8. **Phase 7**: 02-Core/Academy (all 17 stubs) — learning system
9. **Phase 8**: 07-Domains, 08-Interfaces, 09-Reference — application layer
10. **Phase 9**: 04-Execution/Runtime (providers) — execution layer
11. **Phase 10**: 10-Research — future work

---

## Post-03-04 Deep Audit — New Issues Found

These issues were discovered during the comprehensive subagent scan of all 53 files in 03-Institutions (16 files) and 04-Execution (37 files: 8 Runtime + 29 Security):

### Critical Issues

#### 1. EAS Acronym Collision
`Execution-Auth/000-EAS.md` (Execution Authorization Service) and `Audit/000-EAS.md` (Evidence Audit Service) share the same "EAS" acronym. Throughout the Security volume, both are referenced simply as "EAS" with no disambiguation. Prose like "recorded by EAS" is ambiguous — which EAS?

**Suggested fix**: Rename one. Options: Execution-Auth → `EAZ` / `EZS` / `EPA`, or Audit → `AUD` (Audit doc already uses document ID `AIOS-BBL-AUD-000`).

**Affected files**: 7+ Security files reference both without disambiguation.

#### 2. Missing CCA Documentation
The "CCA" (Capability Certification Authority) is referenced as a core Security Council component — it owns pipeline Stage 5 (capability verification), is listed in the Overview and Architecture service tables, and is referenced by `AZS/002-Capability.md`. Yet no `CCA/` directory or `CCA` document exists anywhere.

**Suggested fix**: Create `CCA/000-CCA.md` documenting the Capability Certification Authority, its role in Stage 5, its interface with AZS (Stages 3-4), and its capability verification algorithm. Alternatively, merge CCA responsibilities into `AZS/002-Capability.md`.

#### 3. Runtime Siloed from Security & Institutions
All 8 Runtime files (`000-Overview.md` through `007-Robotics.md`) discuss Security Kernel, execution tokens, secret stores, entity sessions, and mission scopes extensively — but **zero** cross-references to any Security doc (`Execution-Auth/`, `SSM/`, `Sandbox/`, `AZS/`) or any 03-Institutions doc (`Workers/`, `Organizations/`, `Missions/`). A reader cannot trace the verification→execution pipeline or identify which entities invoke which providers.

**Suggested fix**: Add cross-references from `Runtime/000-Overview.md` to `Security/Execution-Auth/000-EAS.md`, `Security/SSM/000-SSM.md`, `Security/Sandbox/000-Isolation.md`, and `03-Institutions/Workers/000-Overview.md`. Each provider doc should link to its relevant Security components.

**Affected files**: All 8 Runtime/*.md files.

#### 4. IRS/IDS Naming Inconsistency (Not Just Paths)
The identity authority is called "IRS" (Identity Registration Service — the constitutional authority) in some places and "IDS" (Identity Service — the implementation) in others, even within the same document. Documents in 03-Institutions mix these interchangeably:

| File | Line(s) | IRS | IDS |
|------|---------|-----|-----|
| Missions/000-Lifecycle.md | 30, 45, 77 | Line 45 | Lines 30, 77 |
| Organizations/000-Overview.md | 32, 119 | Line 119 | Line 32 |
| Workers/000-Overview.md | 50, 71 | Line 71 | Line 50 |
| Workers/001-WOM.md | 24, 81 | Line 24 | Line 81 |

**Suggested fix**: Standardize: use "IRS" for constitutional/architectural references (invariants, source laws), add a note that "IDS" is the implementation service that realizes IRS. Align all docs.

#### 5. Broken Links in 002-Trust-Model.md
- `TLM/000-TLM.md` → directory is `Trust/`, not `TLM/`
- `Cryptography/000-CSP.md` + `Cryptography/001-CAM.md` → directory is `Crypto/`, not `Cryptography/`
- `Federation/000-Overview.md` → no Federation/ dir under Security. Actual file at `06-Services/Federation/000-Overview.md`
- `00-Foundations/001-AIOS-Philosophy.md` → relative path from Security/ resolves incorrectly (should be `../../00-Foundations/...`)

**Affected files**: `Security/002-Trust-Model.md`

#### 6. Broken Links in Execution-Auth/000-EAS.md
References three non-existent files:
- `Bible/0270-CCA.md` ← doesn't exist (CCA has no docs)
- `Bible/0260-ROS.md` ← doesn't exist
- `Bible/0430-Execution-Engine.md` ← doesn't exist

Also missing `Supersedes`, `Superseded By`, `Amended By` metadata rows.

### Medium Issues

#### 7. Acronym Overload in Organizations/000-Overview.md
The "Organization Types" table uses acronyms (OOM, OHS, ODS, OPE, etc.) that match document filenames but with **different semantic meanings**:
- `OOM` in type table = "Operational Oversight — monitoring and governance body"
- `001-OOM.md` document = "Organization Object Model" (canonical schema)
- `OPE` in type table = "Project/Program Entity"
- `008-OPE.md` document = "Organization Performance Evaluator"

This creates confusion when reading cross-references.

**Suggested fix**: Either rename the type table entries to use different acronyms, or add a clarifying footnote explaining the dual usage.

#### 8. ID Format Contradiction (IDS-000 vs IDS-001)
- `IDS/000-Overview.md` line 76: `aios:${entity_type}:${random_suffix}`
- `IDS/001-Registry.md` line 57: `aios:{entity_type}:{entity_id_hash}:{random_suffix}`

Two different ID formats in sibling documents. The second includes an `entity_id_hash` segment not present in the first.

#### 9. entity_type Enum vs Entity Types Table (IDS-001)
`IDS/001-Registry.md` line 20: `Enum entity_type { Sou, Organization, Department, Mission, Session, Template, Runtime, Engine, User, Credential }`
Entity Types table (lines 33-44): uses lowercase abbreviations (`org`, `dept`, `mission`) and includes `entity` and `capability` not in the enum.

#### 10. Document ID Format Inconsistency
- `AIOS-BBL-XXX-NNN` (used by IDS-000, Audit, AZS)
- `AIOS-BIBLE-XXX-NNN` (used by IDS-001 through IDS-005)

Same group, two different formats.

#### 11. Category Naming Inconsistency
Two conventions used across Security docs:
- `"Bible — Execution/Security / <subcategory>"` — CSP, CAM, Audit
- `"Bible — Security / <subcategory>"` — EAS (Execution-Auth), all IDS docs

Should be unified.

#### 12. Law Numbering Format Inconsistency
- `"Law N — Name"` (no slash) — CSP, CAM, IDS-000, IDS-001, IDS-002
- `"Law/N — Name"` (with slash) — EAS (Execution-Auth), IDS-003, IDS-004, IDS-005

Some files (e.g., `Execution-Auth/000-EAS.md`) mix both formats within the same document.

#### 13. ATS Sub-Docs Missing Related Documents Sections
`ATS/000-Auth-Methods.md`, `ATS/001-MFA.md`, `ATS/002-Session-Mgmt.md` lack the `## Related Documents` section that every other Security doc has. This is a structural inconsistency.

#### 14. IDS Inter-Doc Relative Paths Broken
`IDS/000-Overview.md` references sibling docs as `IDS/001-Registry.md`, `IDS/002-Resolution.md`, etc. — but from within the `IDS/` directory, this doubles the path to `IDS/IDS/001-Registry.md`. Should be simply `001-Registry.md`.

#### 15. IDS-002 Misleading Heading
Section titled "REST (over ACF)" but operations use method `"RPC"` with dot-notation endpoints. This is RPC, not REST.

#### 16. Duplicated Content in IDS
- `IDS/004-Federation.md` lines 46-56 are nearly verbatim from `IDS/002-Resolution.md` lines 42-51 ("Pipeline Integration")
- `IDS/005-Provenance.md` lines 67-81 largely duplicate `IDS-001-Registry.md` lines 71-83 ("Audit Trail")

#### 17. Incomplete IDS Documents
`IDS/002-Resolution.md`, `IDS/004-Federation.md`, `IDS/005-Provenance.md` are missing standard sections:
- `## Events` table
- `## Cross-Cutting Concerns`
- `## Design DNA` (R1-R15 assessment)
- `## Related Documents`

They end abruptly or lack these sections present in all other IDS docs.

#### 18. OrgType Enum Mismatch
`Organizations/001-OOM.md` defines a 4-type `OrgType` enum (`root`, `department`, `team`, `committee`) while `Organizations/000-Overview.md` defines an 8-type organization taxonomy. No explanation of the relationship between the two.

#### 19. Missing Metadata Rows
- `Execution-Auth/000-EAS.md`: missing `Supersedes`, `Superseded By`, `Amended By`
- `IDS/003-Lifecycle.md`: missing same rows
- `IDS/005-Provenance.md`: missing same rows

#### 20. Source Laws Missing Documented Dependencies
- `Sandbox/000-Isolation.md`: body references Law 6 (Lifecycle) and Law 10 (Tenure), but neither is listed in Source Laws front matter
- `SSM/000-SSM.md`: body discusses Law 6 (Lifecycle Compliance) extensively but it's missing from Source Laws

#### 21. PVE Related Documents Description Inverted
`Policy-System/002-PVE.md`: Related Documents entry for `../Execution-Auth/000-EAS.md` says "Stage 4 evaluation depends on PVE-validated policies" — dependency direction is inverted. Should read "PVE provides validated policies consumed by Stage 4".

#### 22. WSS Security Escalation Codes Not Listed
`Workers/003-WSS.md` defines security escalation codes `WSS_SEC_001` through `WSS_SEC_005` in the Security Escalation Levels table, but the R12 Error Codes section only lists `WSS_001` through `WSS_006`. The security codes appear to belong to a different namespace with no explanation.

### Systemic Gaps

#### A. No Cross-References from Security to 03-Institutions
Zero documents in `04-Execution/Security/` reference any document in `03-Institutions/`. Security docs discuss Workers (autonomy levels, sandbox types, risk weights), Organizations (org policies, trust), and Missions (mission policies, risk) extensively — but never link to the documents that define those entities. This means readers of the Security docs cannot navigate to the entity definitions they reference.

**Affected files**: All 29 Security/*.md files.

#### B. No Cross-References from Runtime to 03-Institutions
Same gap for Runtime: all 8 providers discuss entities, Worker Sessions, missions, and organizations but never link to their definitions.

**Affected files**: All 8 Runtime/*.md files.

#### C. All Physics Links Still Broken
All 53 files reference `Physics/XXX.md` with deep relative paths from within `Bible/03-Institutions/` or `Bible/04-Execution/`. The `Physics/` directory is at the project root (`full plan bible/Physics/`), not inside `Bible/`. Every single one of these ~100+ references is a dead link. This was flagged in the previous audit and remains unresolved.

#### D. No ACF Cross-References
Both Runtime and Security docs reference ACF (Agent Communication Framework) as the communication substrate — "ACF stream", "ACF/RPC" — but never link to the ACF documentation (`06-Services/ACF/`). No central ACF topic registry exists.

### Quick-Fix Items (Low Effort, High Impact)

1. Fix `IDS/000-Overview.md` self-references: remove `IDS/` prefix from `IDS/001-Registry.md` etc.
2. Add `## Related Documents` sections to ATS/000, ATS/001, ATS/002 (model on sibling docs)
3. Add missing metadata rows to EAS (Execution-Auth), IDS-003, IDS-005
4. Fix `002-Trust-Model.md` directory names: `TLM/`→`Trust/`, `Cryptography/`→`Crypto/`, `Federation/`→ correct path
5. Fix `002-Trust-Model.md` `00-Foundations/` relative path
6. Remove or fix non-existent `Bible/0270-CCA.md`, `Bible/0260-ROS.md`, `Bible/0430-Execution-Engine.md` references in EAS
7. Fix `PVE/002-PVE.md` inverted dependency description
8. Fix IDS-002 heading "REST"→"RPC"
9. Remove duplicated content in IDS-004 and IDS-005

### Needs Discussion (Architecture Decisions)

1. **EAS acronym**: Which service gets renamed?
2. **CCA**: New document or merge into AZS/002-Capability.md?
3. **Physics/ vs Bible/00-Physics**: Should Physics live alongside Bible or inside it?
4. **OrgType relationship**: Are the 8-type and 4-type taxonomies orthogonal (structural vs functional) or do they need reconciliation?
5. **ID format**: `aios:{entity_type}:{random_suffix}` or `aios:{entity_type}:{entity_id_hash}:{random_suffix}`?
6. **Document ID prefix**: `BBL` or `BIBLE`?
7. **Category prefix**: `Execution/Security` or just `Security`?
8. **Law format**: `Law N` or `Law/N`?

---

*This document is a living suggestion. Priority may change based on implementation needs. Files marked High in this document should be written before implementation begins on related Components.*

---

## Post-02-Core Audit — Issues Found

These issues were discovered during supervisor review of 52 newly written 02-Core files:

### Incorrect Law References in ROS
- ROS files (000-014) use `Law 8 — Law of Proportionality` and `Law 12 — Law of Bounded Capability` as Source Laws. There are only 10 constitutional laws (0-9) and Law 8 is canonically `Law 8 — Law of Verification-First` across all other Bible volumes. These references must be aligned to actual Law names from Physics/000-Laws.md.
- **Affected files**: All 15 ROS/*.md files.

### Aspirational Cross-References
- **Academy/000-Overview.md**: References `Physics/012-Experience.md` — this Physics document exists in the `physics/` directory but the cross-reference format in Bible docs should be verified.
- **ROS/014-RXP.md**: References `IDS/003-PKI.md` — this file does not exist. The PKI/certificate authority specification lives in `06-Services/Cryptography/Certificates/`.
- **AGS/001-Composition.md**: References `merge()` operation without specifying authorization model (who may merge Genomes).

### Design Considerations
- **DTS/004-Confidence.md**: Confidence weights are hardcoded (evidence 40%, simulation 30%, precedent 20%, trust 10%). Consider making these configurable per-decision-type or learnable through the Academy.
- **OSYS/002-Org-Lifecycle.md**: Organization hierarchy depth limit of 7 levels is stated without rationale. Should be justified with capacity/performance reasoning.
- **Academy/016-Knowledge-API.md**: At 423 lines, this file exceeds the 200-400 line target. Consider splitting into API specification + rate limiting/authorization as a separate doc.
- **ROS/000-006**: Several ROS overview files (000-Overview, 001-Architecture, 002-Registry, 003-Allocator) are 153-189 lines, slightly below the 200-line guideline. Content is substantively complete — may warrant a guideline relaxation for overview documents.

### Knowledge Boundary Clarifications
- **Sou Knowledge vs Academy Knowledge**: The handoff protocol for Sou sharing private knowledge with Academy (ACF stream types, privacy filter specifics) is referenced as TBD across both Sou/005-Knowledge.md and Academy docs. Needs alignment during implementation.
- **Identity Lifecycle Alignment**: OSYS/002-Org-Lifecycle.md defines 7 states (Created → Verified → Active → Suspended → Restored → Dissolved → Archived). This matches the canonical identity lifecycle in IDS/003-Lifecycle.md except `Dissolved` replaces `Retired`. Verify this is intentional (organizations dissolve rather than retire).

### Missing Dependencies
- **No Physics/000-Laws.md reference in many files**: Several 02-Core files do not reference the foundational Laws document directly. While they reference Physics invariants, the source Law should be explicit.
- **ACF protocol details**: Several files reference ACF stream topics (e.g., `academy.knowledge.proposed`) but no central ACF topic registry exists yet. These topic names should be consolidated in a future ACF specification.

## Post-03-05-06 Audit — Issues Found

These issues were discovered during supervisor review of 61 newly written files (03-Institutions: 16, 05-Platform: 14, 06-Services: 31):

### Critical (Fixed)
- **05-Platform/010-TEE.md**: Duplicate `## TEE Invariants` and `## Performance Characteristics` sections removed. The second Invariants set used `Freshness` (INV-005) vs original `No Persistence`; kept original.
- **05-Platform/008-BG.md**: Redundant `## BG Invariant Summary` section (duplicated `## BG Invariants`) removed.
- **06-Services/Cryptography/Random/000-Random.md**: Duplicate `## Cross-Cutting Concerns` section removed.
- **06-Services/Cryptography/000-CSP.md**: Typo fixed (`non-sensive`→`non-sensitive`, `sensive`→`sensitive` in ASCII diagram).
- **06-Services/Federation/000-Overview.md**: Duplicate Cross-Cutting Concerns subsections (Security, Evidence, Lifecycle, Capability Bounds appeared twice) removed.

### Structural Gaps (Fixed)
- Added missing **Events tables** and **Communication** subsections to 4 Crypto files: Certificates, HSM, KMS, Signatures.

### Law Numbering — Systemic Inconsistency (Not Fully Resolved)
The Bible has TWO conflicting law numbering conventions used interchangeably:

| Law | Scheme A (Governance/Foundations) | Scheme B (02-Core, 05-Platform, 06-Services) |
|-----|----------------------------------|----------------------------------------------|
| 1 | **Evidence** | Origin / Identity |
| 2 | Constitutional Supremacy | Non-Execution / Autonomy |
| 3 | Communication | Capability Bounds |
| 4 | *(unused)* | **Evidence** (dominant) |
| 5 | Identity | Capability Bounds |
| 6 | Lifecycle | Lifecycle |
| 7 | Capability Bounds | Capability Bounds |
| 8 | Verification-First | Verification-First |
| 9 | Design DNA | Design DNA / Deterministic |
| 10 | Tenure | Tenure / Execution |

**Fixed**: Non-existent laws 12, 13 removed. "Law 8 — Proportionality" and "Law 12 — Bounded Capability" in ROS → canonical Law 7 — Capability Bounds. "Law 3 — Capability Bounds" across multiple files → Law 7. "Law 5 — Capability Bounds" → Law 7. "Law 1 — Identity" → Law 5.

**Resolution needed**: Physics/000-Laws.md (the source of truth) doesn't exist yet. Once written, it should establish definitive Law 0-10 names, and all files should be bulk-updated to match.

### Broken Cross-References (Systemic — Not Fixed)
- **`Physics/` directory does not exist**: All ~100+ references to `Physics/XXX.md` are unresolvable. These files need to be created as the normative layer above Bible.
- **Relative paths are wrong**: Files use absolute-style paths (e.g., `05-Platform/004-EVS.md` from `ACF/`) instead of correct relative paths (`../../05-Platform/004-EVS.md`). This applies to ~50+ cross-references across the new files.
- **Prefix inconsistency**: Some references use `Foundations/` instead of `00-Foundations/`.

### Missing Law 3 in ACF Files (Not Fixed)
All 8 ACF files cite Law 4 (Evidence) and Law 5 (Identity) but none cite **Law 3 — Communication**, which should be the primary source law for the communication fabric itself.

### Federation Files — Missing Law References (Not Fixed)
Only 2 of 13 Federation files (000-Overview, 012-IXP) have all three expected laws (4, 5, 8). The other 11 miss Law 5 (Identity) and/or Law 8 (Verification-First).

### 03-Institutions — Directory-Path Cross-References (Not Fixed)
9 references across 6 files point to IDS/ATS directories rather than specific `.md` files (e.g., `Bible/04-Execution/Security/IDS` instead of `Bible/04-Execution/Security/IDS/000-Overview.md`).

### Incomplete Design DNA (Not Fixed)
Several Crypto files list only 3-5 of 15 Design DNA rules. Should be expanded to cover all rules:
- Certificates: only R3, R10, R13
- HSM: only R1, R10, R13, R14
- KMS: only R1, R6, R10, R13, R14
- Signatures: only R1, R9, R10, R14
- Random: only R1, R9, R10, R13, R14 (after dedup)

### ACF Overview Missing Formal Cross-Cutting Concerns (Not Fixed)
ACF/000-Overview.md has Security Model, Design Decisions, and Performance Targets but lacks the standard `## Cross-Cutting Concerns` section with 6 subsisters found in all other ACF files (001-007). This is somewhat acceptable for an overview but should be aligned.

### 05-Platform Cross-Reference Issues
- 003-PSAP.md references `Standards/004-PSAP.md` — Standards/ directory does not exist.
- Several files reference `Foundations/008-Object-Lifecycle.md` instead of `00-Foundations/008-Object-Lifecycle.md`.
- 010-TEE.md references `Crypto/000-Overview.md` — actual file is `Crypto/000-CSP.md`.
- 012-CP.md references `ATS/000-ATS.md` — actual file is `ATS/000-Auth-Methods.md`.

## Reference/ — New Files Written

Three files were created in the root `Reference/` directory (previously empty stubs):

### 000-Architecture-Decision-Log.md (169 lines)
Master log of 15 key architectural decisions (ADR-001 through ADR-015). Each entry has context, rationale, alternatives considered, and Bible references.

**Suggestions for future**:
- Add an "Author" field to each ADR entry to match the Bible's detailed log
- Mark which ADRs correspond to constitutional amendments vs. architectural decisions
- Consider adding a "Consequences" field per entry (what changes were required)

### 001-ADG.md (123 lines)
Quick-reference guide for the Architectural Decision Gateway — when ADG is needed, entry format, lifecycle, review criteria, ADG→RFC handoff, and summary index of all 13 ADG entries.

**Suggestions for future**:
- Add a decision tree or flowchart (text-based) for "Do I need an ADG?"
- Link each ADG entry in the summary table to its detailed Bible doc
- Add typical review timeline expectations (how long does ADG review take?)

### 002-Reference-Architecture.md (268 lines)
High-level architecture map including system layering, constitutional 4-branch diagram, full ASCII component map, 7-stage security pipeline, key data flows (Identity, Execution, Knowledge, Security/Auth), Design DNA table (R1–R15), and Bible navigation guide.

**Issues to resolve** (mirrored from Bible audit):
- **EAS acronym collision**: Pipeline Stage 7 (Execution Authorization Service) and the Audit service (Evidence Audit Service) both use "EAS". The Reference Architecture explicitly documents this collision but the Bible documents still need resolution.
- **CCA missing**: Stage 5 (CCA — Capability Certification Authority) is shown in the pipeline but the CCA document doesn't exist in `Bible/04-Execution/Security/`. Either create it or document where CCA responsibilities live.
- **IRS/IDS naming**: ADR-005 was renamed from "IRS" to "IDS" in the log, but the Bible still mixes both names.

### SDK/ — All 3 Files Written

All three developer quick-start docs are complete with installation, code examples, implementation checklists, common patterns, and conformance testing instructions.

**Suggestions for future**:
- Add a **Events** section to each SDK file listing the specific Events each provider must emit, matching the Bible specs
- Add **Design DNA compliance** table to each SDK file for consistency with Bible format
- Add **Cross-Cutting Concerns** section (Security, Evidence, Lifecycle, Capability Bounds) to match Reference files
- **Missing Provider-SDK stub**: The Bible has `003-Provider-SDK.md` but the root SDK/ directory doesn't have a corresponding file. Consider adding it for developers building resource providers (ROS integration). The Bible file exists at `Bible/08-Interfaces/SDK/003-Provider-SDK.md`.

### Standards/ — All 5 Files Written

| File | Lines | Content |
|------|-------|---------|
| 000-Design-Language.md | 104 | Typography, diagram conventions, vocabulary, color/style, document structure |
| 001-Naming-Conventions.md | 114 | File/code/DB/API/ACF naming, document IDs, error codes, event types, versioning |
| 002-BAS.md | 132 | Document template, metadata rules, required sections, cross-reference format, length guidelines, status lifecycle, Design DNA compliance |
| 003-DQC.md | 96 | 40-item mandatory checklist across 8 categories, quality levels L0-L3, automation candidates |
| 004-PSAP.md | 116 | Service naming, registration fields, endpoint format, health check contract, heartbeat requirements, load balancing, error codes |

**Issues found and fixed during review**:
- Design Language: Fixed broken code block example (nested backtick fences), replaced ambiguous EAS acronym example with IDS, added missing Cross-Cutting Concerns section
- Naming Conventions: Fixed angle bracket casing (`<Kebab-Case>` → `<kebab-case>`), clarified document ID table with top-level dirs, added dual event type format note (DB vs ACF), added SDK/REF/STD prefix docs
- BAS: Added document status lifecycle (Draft→Active→Deprecated→Superseded) with TBD/TODO handling rules, clarified cross-reference paths (absolute from project root, not relative)
- DQC: Added self-consistency check for Standards documents, fixed document ID format check to cover non-Bible docs (STD-, SDK-), added "all 6 CCC subsections" check
- PSAP: Fixed "no hyphens" contradiction with naming patterns (hyphens allowed in compound names), fixed error codes to use underscores (`PSAP_001` not `PSAP-001`) matching naming convention, added Cross-Cutting Concerns section

**Suggestions for future**:
- Align the Bible's PSAP error codes (`PSAP-001` with hyphens) with the naming convention (`PSAP_001` with underscores) — the Standards now say underscore but the Bible uses hyphen
- Consider moving the ACF topic naming patterns from Naming-Conventions into a dedicated ACF standards doc under Standards/
- The BAS template lengths (150-500 lines) may be tight for comprehensive specification documents; consider periodic review

### RFC/ — All Files Written

| File | Lines | Content |
|------|-------|---------|
| 000-RFC-Process.md | 105 | Step-by-step RFC lifecycle guide: when RFC is required, 5-step process (Draft→Submit→Review→Implement→Verify), review SLAs by type (24h to 14d), 3 checklists (pre-submit/implementation/activation) |
| Templates/RFC-template.md | 86 | RFC template with Problem Statement, Proposed Solution, Impact Analysis, Evidence, Constitutional Review, Design DNA (R1-R15), Migration Plan, Review Notes, Priority field, Changelog |
| 0001-XXXX/README.md | 7 | Placeholder guide for creating the first RFC |

**Issues found and fixed during review**:
- Fixed contradictory instructions in Step 1 vs Step 2: unified directory creation flow (create dir first, then copy template into it)
- Added missing pre-submit checklist item for directory structure
- Added `Bible/00-Foundations/002-Design-DNA.md` to Related Documents
- Added **Priority** field (Standard/Critical) to template — expedited reviews use `Priority: Critical`
- Added default `Nothing` to template's `Amended By` field
- Added **Changelog** section to template for tracking revisions during review
- Fixed README.md instructions to match the corrected process flow

### APIs/000-Master-API-Spec.md — Complete

Written and audited. 536 entries across 9 service groups covering every concrete API endpoint, ACF topic, RPC method, streaming channel, interface, event, and message type.

**Issues found and fixed during audit:**
- 3 fabricated EPG events removed (`PipelineStarted`, `PipelineCompleted`, `PipelineFailed`)
- 1 fabricated ACF topic removed (`aios/{domain}/{service}/{instance}/health`)
- 130+ missing events added across PSAP, EVS, EPG, EIP, CP, Graph Framework, LMS, Knowledge Search, KMS, AZS, CSP, WCS, WSS, Playbook, OIS, Trading, Security Domain
- 9 missing RPC methods added (EVS: 4, WCS: 5)
- 5 missing Audit SDK methods added
- 4 wrong event names corrected (EPG: `GraphDeployed`→`GraphActivated`, `GraphUndeployed`→`GraphDeactivated`; LMS: `EntityStateChanged`→`StateChanged`, `TransitionRejected`→`TransitionDenied`)
- 15 Playbook events: corrected case (`Playbook.`→`PLAYBOOK.`), removed 1 fabricated event, added 10 missing events
- 4 source paths fixed to include `Bible/` prefix
- 4 Security domain entries reclassified from `RPC` to `Capability`
- Ollama auth corrected from `API Key` to `Network-bound (localhost/private)`
- PSAP methods corrected from ACF routing operations to actual PSAP service registry operations

### Phase 3 Bug Fixes Applied During Audit

- **SIM**: Invariant SIM-003 referenced "(Law 9)" — wrong, Law 9 is Constitutional Supremacy, not determinism. Changed to reference Design DNA R9 (Deterministic) instead.

### Phase 3 Bug Fixes Applied During Audit

- **SIM**: Source Laws incorrectly referenced Law 9 (Constitutional Supremacy) as "Deterministic" — no such Physics Law exists. Replaced with Law 6 (Lifecycle Compliance).
- **SIM**: Core Concept 1's embedded `Scenario` interface snippet was out of sync with the authoritative Data Model definition. Replaced with a cross-reference pointer.
- **SIM**: Added missing internal interfaces for `ScenarioBuilder`, `EvidenceRecorder`, `ReplayEngine`, and `HypothesisManager` (referenced in Component Map but missing from Internal Interfaces section).
- **SIM**: Data flow diagram had ambiguous indentation — "Sandbox destroyed" appeared to belong only to the failure branch. Clarified with "(both paths)" annotation.

### Phase 2 Suggestions (non-critical, additive)

These were identified during the Phase 2 audit but are enhancements, not bugs:

- **WFE**: The state machine ASCII diagram (`Bible/04-Execution/Workflow/000-Overview.md:70-77`) has ambiguous arrow alignment — the Running→Failed transition path overlaps visually with the Ready→Completed path. Worth redrawing for clarity.
- **Cross-references**: No existing docs currently reference WFE or IOP in their Related Documents tables. Candidate files that could benefit:
  - `Bible/02-Core/Brain/000-Overview.md` — add WFE and IOP as related external systems
  - `Bible/04-Execution/Security/000-Overview.md` — WFE uses EAS for step authorization
  - `Bible/06-Services/ACF/000-Overview.md` — IOP builds on top of ACF transport
- **AGX**: Consider splitting into sub-docs (like CCA has 000-CCA.md, 001-CAS.md, 002-CDG.md) once the system matures — e.g., separate docs for the Evolution Engine, Genome Repository, and Competency Registry specifications.

### Remaining work:
- **Research/** (4 files): Phases 2-5 roadmap
- **Contributing/**, **Examples/**, **Tests/**: Lower priority