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