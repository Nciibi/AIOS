# AIOS Reference
## 002 — Reference Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Reference |
| Document ID | REF-ARCH-002 |
| Source Laws | All 10 Laws |
| Source Physics | Physics/000-Laws.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document provides the high-level reference architecture for AIOS. It describes the system's layered structure, key components, data flows, and architectural patterns. This is the entry point for understanding how AIOS fits together — the Bible contains the detailed specification; this document provides the map.

---

## System Layering

AIOS is organized into six tiers, each with decreasing immutability:

```
  DNA              Who are we?          Philosophical truth    Never changes
  Constitution     What is allowed?     Governance truth       Rarely amended
  Physics          What must be true?   Mathematical truth     Never violated
  Bible            How is it built?     Engineering truth      Continuously evolves
  RFC              How do we change?    Process truth          Transient
  Code             Implementation       Machine truth          Must obey Bible
```

Each tier constrains the tier below. Code must obey the Bible, which must obey Physics, which must obey the Constitution, which must derive from the DNA.

---

## Constitutional Architecture

The Constitution establishes four branches of government:

```
┌─────────────────────────────────────────────────────────────┐
│                    HUMAN SOVEREIGNTY                         │
│              (Article I — Source of Authority)               │
│         Human Override is the only escape valve             │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┬────────────────┐
          ▼                ▼                ▼                ▼
┌─────────────────┐ ┌───────────┐ ┌──────────────┐ ┌──────────────┐
│   STRATEGIC     │ │  EXECUTIVE │ │   JUDICIAL   │ │   SECURITY   │
│    (Sou)        │ │  (OSYS)   │ │  (Academy)   │ │  (Council)   │
│                 │ │           │ │              │ │              │
│ Proposes        │ │ Executes  │ │ Learns       │ │ Verifies     │
│ strategy and    │ │ operations│ │ from events  │ │ every action │
│ missions        │ │ via       │ │ and produces │ │ through      │
│ Never executes  │ │ Workers   │ │ knowledge    │ │ 7-stage      │
│ (Law 2)         │ │           │ │              │ │ pipeline     │
└─────────────────┘ └───────────┘ └──────────────┘ └──────────────┘
```

---

## High-Level Component Map

```
┌──────────────────────────────────────────────────────────────────┐
│                        HUMAN INTERFACE                            │
│              (API Gateway, CLI, Web UI, ACF Bridge)               │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│                        SOU (Strategic Branch)                     │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐   │
│  │Reasoning│ │ Planning │ │ Missions │ │   Knowledge       │   │
│  │ Engine  │ │  Engine  │ │Registry  │ │   Store (Private) │   │
│  └─────────┘ └──────────┘ └──────────┘ └───────────────────┘   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│                      OSYS (Executive Branch)                      │
│                                                                   │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │  Organizations  │  │    Workers     │  │    Missions      │   │
│  │  (Org Tree,    │  │  (Sessions,    │  │  (Lifecycle,     │   │
│  │   Governance)  │  │   Isolation)   │  │   Tracking)      │   │
│  └────────────────┘  └────────────────┘  └──────────────────┘   │
│                                                                   │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │      ROS       │  │   Templates    │  │   Platform       │   │
│  │  (Resources,   │  │   (AGS —       │  │   (LMS, EVS,     │   │
│  │   Allocation)  │  │    Genomes)    │  │    PSAP, BG)     │   │
│  └────────────────┘  └────────────────┘  └──────────────────┘   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│                 SECURITY COUNCIL (Security Branch)                │
│                                                                   │
│   ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────┐ │
│   │ IDS  │ │ ATS  │ │ AZS  │ │  PS  │ │ CCA  │ │ RE   │ │EAS │ │
│   │Identity│ │Auth-N│ │Auth-Z│ │Policy│ │Capab│ │Risk  │ │Exec│ │
│   │       │ │      │ │RBAC +│ │      │ │      │ │      │ │Auth │ │
│   │       │ │      │ │ABAC +│ │      │ │      │ │      │ │    │ │
│   │       │ │      │ │Capab │ │      │ │      │ │      │ │    │ │
│   └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └────┘ │
│                                                                   │
│   7-Stage Verification Pipeline (Stage 1→7, no stage skipped)    │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│                   ACADEMY (Judicial Branch)                       │
│                                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │  Event   │ │Knowledge │ │    KEE   │ │   Knowledge      │   │
│  │  Ingest  │ │   Graph   │ │Execution │ │   Distribution   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│                     RUNTIME EXECUTION LAYER                       │
│                                                                   │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────┐ │
│  │ Claude │ │ Codex  │ │ Ollama │ │Browser │ │ Trading│ │Robo│ │
│  │Provider│ │Provider│ │Provider│ │Provider│ │Provider│ │ ...│ │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Runtime Manager (SDK)                        │    │
│  │  Token validation → Sandbox → Resource enforcement       │    │
│  └──────────────────────────────────────────────────────────┘    │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│                 INFRASTRUCTURE & SERVICES                         │
│                                                                   │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐   │
│  │   ACF   │ │   EVS    │ │ Crypto   │ │   Federation       │   │
│  │ (Comm)  │ │(EventStore)│ (CSP/CAM) │ │   (Cross-Instance) │   │
│  └─────────┘ └──────────┘ └──────────┘ └────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Seven-Stage Verification Pipeline

Every action in AIOS passes through the Security Council's verification pipeline before execution:

```
Action Request
     │
     ▼
┌─────────────┐
│ Stage 1: IDS │  Who is the actor?  Identity verification
└──────┬──────┘
       ▼
┌─────────────┐
│ Stage 2: ATS │  Are they who they claim?  Authentication
└──────┬──────┘
       ▼
┌─────────────┐
│ Stage 3: AZS │  Are they allowed?  Authorization (RBAC + ABAC)
└──────┬──────┘
       ▼
┌─────────────┐
│ Stage 4: PS  │  Does policy allow it?  Policy evaluation
└──────┬──────┘
       ▼
┌─────────────┐
│ Stage 5: CCA │  Do they have the capability?  Capability verification
└──────┬──────┘
       ▼
┌─────────────┐
│ Stage 6: RE  │  What is the risk?  Risk scoring (deterministic + ML)
└──────┬──────┘
       ▼
┌─────────────┐
│ Stage 7: EAZ │  Execution token issued or denied
└──────┬──────┘
       │
       ▼
  Action Executed
```

Each stage produces evidence recorded by the Audit EAS (Evidence Audit Service). The pipeline is linear and mandatory — no stage may be skipped.

---

## Key Data Flows

### Identity Flow
```
Entity Created → IDS issues identity → Registered in Registry →
Identity lifecycle managed by IDS (7 states: Created → Verified →
Active → Suspended → Restored → Retired → Archived)
```

### Execution Flow
```
Mission Created → Resource Budget Allocated (ROS) → Worker Session
Created (Template via AGS) → Capability Bounds Declared → Security
Council Verifies → Execution Token Issued → Runtime Executes on
Provider → Events Recorded (EVS) → Academy Learns from Events
```

### Knowledge Flow
```
Events Produced (by every action) → EVS Stores → Academy Ingests →
Knowledge Graph Updated → Patterns Extracted → Knowledge Distributed
to Entities → Entities Act on Knowledge → New Events Produced
```

---

## Design DNA (R1–R15)

The architecture is governed by 15 design rules defined in Physics/011-Design-DNA.md:

| Rule | Principle | Architectural Expression |
|------|-----------|-------------------------|
| R1 | Modulsingularity | Each component has exactly one responsibility |
| R2 | Acyclic Dependencies | Dependency graph is a directed acyclic graph |
| R3 | DRY | Every concept defined once; reference by ID |
| R4 | Builder-Supplier | Components build things; components use things |
| R5 | Interface-Implementation | Interfaces are stable; implementations evolve |
| R6 | Abstract-Implement | Depend on interfaces, not implementations |
| R7 | Testability by Contract | Every module must be testable in isolation |
| R8 | Performance by Design | Performance targets defined at design time |
| R9 | Deterministic by Default | Same inputs always produce same outputs |
| R10 | Minimalism | Simplest solution that satisfies requirements |
| R11 | Fail-Fast | Errors detected as early as possible |
| R12 | Transparency | All state changes visible and auditable |
| R13 | Graceful Failure | Failure of one component does not cascade |
| R14 | Paved Path | Preferred approach is the easiest approach |
| R15 | Open-Closed | Open for extension, closed for modification |

---

## Cross-Cutting Concerns

### Security
Every action is verified by the 7-stage Security Pipeline. No action executes without an execution token. All verification is evidenced.

### Evidence
Every action produces at least one Event. Events are stored immutably in the Event Store (EVS). The Evidence Audit Service (EAS) provides query access to the evidence chain.

### Lifecycle
Every entity follows a deterministic state machine lifecycle managed by LMS. Lifecycle transitions are guarded, evidenced, and auditable.

### Capability Bounds
Every Worker operates within declared capability bounds. Bounds are verified at Stage 5 of the pipeline and enforced by the Sandbox at the OS level.

### Interoperability
All inter-entity communication flows through ACF. Cross-instance communication uses IXP with mTLS. Federation is governed by the Federation service.

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0000-Master-Architecture-Plan.md | Master plan — the overall architecture strategy |
| Bible/0003-Platform-Architecture.md | Platform architecture — LMS, EVS, PSAP |
| Bible/0004-Service-Architecture.md | Service interactions and deployment topology |
| Bible/0005-Domain-Architecture.md | Domain model, entity hierarchy, capability matrix |
| Bible/00-Foundations/004-System-Layers.md | System layering specification |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA rules with detailed rationale |
| Bible/01-Governance/002-DGP.md | Decision Gateway Process |
| Bible/04-Execution/Security/000-Overview.md | Security architecture overview |
| Bible/04-Execution/Security/001-Architecture.md | Security Council architecture |
| Physics/000-Laws.md | The 10 Universal Laws |
| Physics/011-Design-DNA.md | Design DNA physics |
| 000-Architecture-Decision-Log.md | ADR log — key architectural decisions |
