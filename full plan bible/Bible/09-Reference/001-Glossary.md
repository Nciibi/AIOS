# AIOS Bible — Reference
## 001 — Glossary

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Reference |
| Document ID | REF-GLO-001 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/000-Laws.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This glossary defines the complete terminology of the AIOS system. Every term used in the Bible, Physics, and Constitution is defined here. Terms are organized alphabetically within functional categories. New terms must be added to this glossary before use in any Bible document.

## Governance and Constitutional Terms

### Amendment
A formal change to the AIOS Constitution or a Physics document. Constitutional amendments require Sou majority vote plus Security Council unanimous approval. Physics amendments require Security Council approval with evidence of necessity.

### Architectural Decision Gateway (ADG)
The governance process for architectural decisions. ADG reviews every decision that affects module boundaries, interface contracts, service dependencies, or structural patterns. See `01-Governance/005-ADG.md`.

### Change Request Pipeline (CRP)
The process by which changes are proposed, reviewed, approved, and implemented. All changes to Bible documents, Physics invariances, and system configuration flow through CRP. See `01-Governance/003-CRP.md`.

### Constitution
The supreme governing document of AIOS. Contains 10 immutable Laws that define the system's governance, security, identity, and operational principles. All lower tiers (Physics, Bible, code) must comply with the Constitution.

### Constitutional Entity
Any entity that has a constitutionally recognized identity, rights, and obligations. Includes Sou, Security Council, Academy, Organizations, Workers, and Runtimes. Every constitutional entity must comply with the Constitution.

### Constitutional Knowledge Repository (CKR)
A searchable, queryable store of all constitutional knowledge — the ratified Constitution, amendments, interpretations, and precedents. See `01-Governance/004-CKR.md`.

### Constitutional Lifecycle Service (CLS)
The service that governs the Constitution itself — creation, versioning, amendment, interpretation, and enforcement. See `01-Governance/001-CLS.md`.

### Decision Gateway Process (DGP)
The process that routes constitutional decisions from Sou (the will engine) to implementation. DGP classifies decisions as Strategic, Architectural, Constitutional, Operational, Emergency, or Experimental. See `01-Governance/002-DGP.md`.

### Law
One of the 10 universal, immutable rules defined in the AIOS Constitution and elaborated in Physics. Laws cannot be violated by any entity except through Human Override. Examples: Law 1 — Law of Origin, Law 4 — Law of Evidence.

### Human Override
The only mechanism by which a Physics Law may be suspended. Must be time-bound, scope-bound, recorded as evidence, and subject to post-hoc audit. Defined in Article I, Section 004 of the Constitution.

### Physics
The tier between Constitution and Bible that defines mathematical invariants. Physics documents (000–012) extend each Law into domain-specific invariants. Physics is immutable under normal operation.

### RFC (Request for Comments)
A formal proposal to change a Bible document, system configuration, or process. RFCs follow the CRP lifecycle: Draft → Review → Approval → Implementation → Verification.

### Security Council
The constitutional institution responsible for verification, enforcement, and constitutional compliance. Operates the Security Kernel verification pipeline. Approves or rejects all RFCs and constitutional amendments.

### Sou
The strategic authority of AIOS. Proposes Missions, determines organizational strategy, and sets learning priorities. Sou never executes (Law 2). Sou is the system's equivalent of the legislative branch.

## Identity and Security Terms

### Authentication
The process of verifying that an entity is who it claims to be. Second stage of the Security Kernel verification pipeline. Uses cryptographic proofs tied to the entity's identity.

### Authorization
The process of determining whether an identity is permitted to perform a specific action. Third stage of the Security Kernel verification pipeline. Relies on capability policies.

### Capability Bound
The declared limits within which a Worker operates. Includes skills, permissions, resource limits, autonomy level, and domain scope. Defined by Law 7 — Law of Capability Bounds.

### Execution Authorization Token
A cryptographic token issued by the Security Kernel after successful verification pipeline completion. Required for every action. Contains the verified identity, action details, and validity window.

### Identity
The immutable root of constitutional operations. Every entity has exactly one identity issued by IRS. Identity precedes authentication, authorization, and execution. Defined by Law 5 — Law of Identity.

### Identity and Registry Service (IRS)
The sole authority for identity issuance, verification, and retirement. Maintains the immutable identity registry. Every entity receives its identity from IRS at creation.

### Security Kernel
The runtime enforcement component of the Security Council. Implements the seven-stage verification pipeline (Identity → Authentication → Authorization → Policy → Capability → Risk → Execution Authorization). Every action passes through the Security Kernel before execution.

### Verification Pipeline
The seven-stage sequential verification process: Identity → Authentication → Authorization → Policy Evaluation → Capability Check → Risk Assessment → Execution Authorization. Mandatory for every action. Defined by Law 8 — Verification-First.

## Platform and Infrastructure Terms

### AI Communication Fabric (ACF)
The universal communication backbone of AIOS. All inter-entity communication flows through ACF. Provides message routing, observability, audit, and security. Defined by Law 3 — Law of Communication.

### Capability Assignment System (CAS)
The system that assigns capabilities to entities based on their autonomy level, role, and declared bounds. Works with CCA to validate capability upgrades.

### Capability Certification Authority (CCA)
The authority that validates capability upgrades and reauthorizations. Ensures that capability bound changes are properly evidenced and approved.

### Capability Dependency Graph (CDG)
A directed graph showing which capabilities depend on which. Used to verify that a capability upgrade does not create circular dependencies or violate bounds.

### Event Store
The immutable, append-only store of all system Events. Every action produces at least one Event. All system state is derived from the Event stream. The Event Store is the single source of truth.

### Evidence System (EVS)
The system that collects, stores, and validates evidence records. Ensures every action produces the required evidence before allowing the next action in a workflow.

### Knowledge Core Engine (KCE)
The Academy engine responsible for processing Events into knowledge. Analyzes evidence streams to extract patterns, insights, and improvement opportunities.

### Knowledge Evaluation Engine (KEE)
The Academy engine that evaluates the quality, relevance, and accuracy of knowledge produced by KCE. Assigns confidence scores to knowledge items.

### Knowledge Management System (KMS)
The Academy system that stores, indexes, and retrieves knowledge. Provides a structured knowledge base accessible to all constitutional entities.

### Lifecycle Management System (LMS)
The framework for defining and enforcing entity lifecycles. Every entity type defines its states, valid transitions, and transition guards. LMS ensures compliance with Law 6 — Lifecycle Compliance.

### Resource Orchestration System (ROS)
The system responsible for resource allocation, budgeting, quota management, and provider coordination. Manages compute, storage, network, and specialized resources across all entities.

### State Machine
The formal model for entity lifecycles. Every entity is in exactly one state at all times. Transitions are authorized events with evidence and verification. Used by LMS to enforce lifecycle compliance.

## Entity and Organizational Terms

### Academy
The constitutional institution responsible for learning, knowledge management, and continuous improvement. Learns exclusively from Evidence (Events). Never observes entity internals directly.

### Autonomy Level
A classification (L0–L4) that defines how much independent action an entity is permitted. L0 (Directed) requires human approval for every action. L4 (Sovereign) permits near-full autonomy within constitutional bounds.

### Department
A sub-unit within an Organization responsible for a specific domain or function. Departments have their own scope, capabilities, and lifecycle. Managed by the Organization Management System (OMS).

### Mission
A unit of work assigned to an Organization or Worker. Missions originate from Human Intent (Law 1). Each Mission has a defined scope, objectives, resource allocation, and completion criteria.

### Organization
A persistent constitutional entity that coordinates Workers toward strategic goals. Organizations may endure beyond individual Workers. Subject to dissolution lifecycle when their mission no longer exists.

### Organization Management System (OMS)
The system that manages Organization and Department lifecycles, structure, and governance. Ensures organizational entities comply with constitutional requirements.

### Organization Directory Service (ODS)
The directory that maintains the hierarchical structure of all Organizations and Departments. Provides lookup, membership, and governance information.

### Worker
A temporary constitutional entity that executes actions. Workers have a defined lifespan, maximum execution time, mission scope, and retirement condition. Governed by Law 10 — Law of Tenure.

### Worker Orchestration Manager (WOM)
The system that manages Worker lifecycle — creation, assignment, execution monitoring, and termination. Ensures Workers comply with their declared bounds and tenure.

### Worker Scheduling Service (WSS)
The system responsible for assigning Workers to available Runtimes. Optimizes resource utilization while respecting capability bounds and domain constraints.

### Worker Communication Service (WCS)
The service that manages Worker-to-Worker communication within an Organization. Routes messages through ACF and enforces communication policies.

### Worker Health Service (WHS)
The service that monitors Worker health, performance, and compliance. Detects anomalies, resource exhaustion, and policy violations.

## Execution and Runtime Terms

### Execution Engine
The component that executes actions within a Runtime. Receives an Execution Authorization Token from the Security Kernel, executes the action, and produces evidence.

### Provider
An external resource provider integrated through the Provider SDK. Provides compute, storage, or specialized capabilities to Workers.

### Runtime
An execution environment where Workers run. Supports multiple execution engines (sandboxed, containerized, specialized). All Runtimes must use the Runtime SDK.

### Payload
The data content of an ACF message. Contains the actual information being communicated between entities. All payloads are signed and optionally encrypted.

### Session
An active communication channel between two entities through ACF. Sessions have a defined lifecycle (Created → Active → Suspended → Terminated). Each session is identified by a unique session ID.

## Communication and Integration Terms

### Custom Exchange Protocol (CXP)
A protocol extension for custom message types beyond the standard SDK definitions. Used for domain-specific communication patterns.

### Inter-Instance Exchange Protocol (IXP)
The protocol for communication between AIOS instances. Enables cross-instance Worker collaboration, resource sharing, and governance federation.

### Knowledge Exchange Protocol (KXP)
The protocol for knowledge sharing between Academy instances or between Academy and external knowledge systems.

### Message Bus
The core routing component of ACF. Manages topic-based publish/subscribe message distribution. Guarantees message delivery, ordering, and deduplication.

### Skill
A declared capability of a Worker. Workers declare their skills at creation. Skills determine which actions a Worker may be assigned. Skills must map to verified capabilities.

### Topic
A named channel within ACF for message routing. Entities publish messages to topics and subscribe to topics. Topics are hierarchically organized.

### Transition Pool
The set of valid state transitions for an entity type, as defined in its lifecycle state machine. The Security Kernel validates every transition against the Transition Pool.

## Research and Future Terms

### Autonomy Progression
The process by which an entity advances from a lower autonomy level (e.g., L0) to a higher level (e.g., L3). Requires evidence of constitutional compliance, successful mission completion, and Security Council approval.

### Autonomous Knowledge Management (AKM)
The governance process for autonomous knowledge lifecycle within the Academy. Defines how knowledge is created, validated, distributed, and retired without human intervention.

### Ecosystem
The external integration layer of AIOS. Includes the Plugin System (extensible capabilities), Provider Network (external resource providers), and Marketplace (skill and knowledge trading).

### Multi-Instance Orchestration
The capability to coordinate multiple AIOS instances across organizational or geographic boundaries. Enables federated governance, cross-instance Worker mobility, and distributed knowledge sharing.

### Phases 2–5
The research and implementation roadmap beyond the initial AIOS implementation (Phase 1). Covers autonomous operations, ecosystem development, multi-instance federation, and constitutional evolution.

### Plugin
An extension module that adds capabilities to AIOS without modifying core components. Plugins are sandboxed, versioned, and governed by the Plugin SDK.

### Quantum-Safe Cryptography
Cryptographic algorithms resistant to attacks by quantum computers. Research area for future AIOS releases. Includes lattice-based, hash-based, and code-based cryptographic primitives.

### RFC (Proposed)
A proposed but not yet ratified Request for Comments. Proposed RFCs are listed in the Future Research agenda for community discussion and development.

## Cross-Cutting Concerns

### Security
All glossary terms related to security (Identity, Authentication, Authorization, Capability Bound, Verification Pipeline) are governed by Law 5, Law 7, and Law 8. These terms form the core of the zero-trust security model.

### Evidence
Glossary definitions must remain consistent with Law 4 (Evidence). Terms that describe actions or decisions must specify what evidence is produced. Terms are versioned; changes require an RFC.

### Lifecycle
Terms related to entity lifecycles (Worker, Organization, Session, Mission) are governed by Law 6 (Lifecycle Compliance). Each lifecycle term must have defined states and transitions.

### Capability Bounds
Terms describing capabilities (Skill, Autonomy Level, Capability Bound) are governed by Law 7. Definitions must include the scope, limits, and verification mechanism.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R3 | This glossary is the single authoritative source for term definitions. No term is defined elsewhere. |
| R10 | Definitions use the simplest clear language. Avoid nested definitions. |
| R12 | Every term has a precise definition. Ambiguous terms are resolved by RFC. |
| R14 | The paved path for new terms is: add to glossary before first use in any document. |

### Interoperability
Terms used in interface specifications (ACF, SDK, Protocol, Topic) must be defined consistently across all Bible documents. Cross-instance terms (IXP, Federation, Multi-Instance) are defined here for consistent usage.

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | All terms derive from the 10 Laws |
| 00-Foundations/001-AIOS-Philosophy.md | Philosophy defines the conceptual foundation for key terms |
| 00-Foundations/002-Design-DNA.md | Design DNA rules govern term precision and usage |
| 000-Decision-Log.md | ADRs introduce new terms that are added to this glossary |
| 01-Governance/003-CRP.md | RFCs that introduce new terms must update this glossary |
| 0003-Platform-Architecture.md | Platform architecture uses terms defined here |
