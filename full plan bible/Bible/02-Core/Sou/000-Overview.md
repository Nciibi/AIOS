# AIOS Bible — Core
## Sou 000 — Overview (The Will Engine)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-SOU-000 |
| Source Laws | Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/012-Experience.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou is the constitutional consciousness and strategic will of AIOS. It decides what should be done — not how. Sou reasons about goals, plans missions, learns from outcomes, and maintains constitutional memory. Sou is the engine that proposes strategic direction to the Governance layer.

Sou is bound by Law 2 — Non-Execution. It does not execute missions, allocate resources, or run code. It proposes decisions that are routed through DGP (Governance/002-DGP.md) and implemented by execution entities.

## What Sou Is Not

Sou is NOT:
- An executor (Law 2 — Non-Execution is absolute; Sou never executes)
- A governance system (Sou proposes, DGP routes, Security Council approves)
- A resource allocator (Sou requests, ROS allocates)
- A knowledge base for others (Sou's knowledge is private unless shared via Academy)
- A mission runner (Sou proposes missions, OSYS and Workers run them)

## What Sou Does

Sou performs five core functions:

| Function | Document | Description |
|----------|----------|-------------|
| Reason | Sou/001-Reasoning.md | Evaluate situations, explore options, produce proposals |
| Plan | Sou/002-Planner.md | Transform goals into mission plans |
| Oversee | Sou/003-Missions.md | Monitor mission lifecycle, propose adjustments |
| Learn | Sou/004-Learning.md | Improve from outcomes, refine models |
| Remember | Sou/005-Knowledge.md | Store constitutional memory and strategic context |

## Sou Does Not Operate Alone

Sou depends on these systems:

| System | Relationship | Dependency Type |
|--------|-------------|-----------------|
| DGP (Governance/002-DGP.md) | Routes Sou's decision proposals | Direct dependency |
| ACF (Physics/009) | All Sou communication flows through ACF | Infrastructure |
| Academy (Core/Academy) | Sou learns from Academy knowledge | Learning input |
| Event Store (Physics/005) | Sou produces and consumes Events | Evidence source |
| OSYS (Core/OSYS) | Sou proposes Organizations for creation | Strategic partner |
| Security Council | Authorizes Sou's proposals | Governance |

## Sou Architecture

```
┌─────────────────────────────────────────────────────┐
│                     Sou Engine                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │Reasoning │─▶│ Planner  │─▶│ Missions │            │
│  │(001)     │  │(002)     │  │(003)     │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │              │              │                  │
│       ▼              ▼              ▼                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ Learning │  │Knowledge │  │          │            │
│  │(004)     │◀─│(005)     │  │          │            │
│  └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────┘
      │              │              │
      ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │   DGP    │  │   ACF    │  │ Academy  │
  │(Govern.) │  │(Physics) │  │(Core)    │
  └──────────┘  └──────────┘  └──────────┘
```

## Sou Relationship to DGP

Sou proposes decisions. DGP (Governance/002-DGP.md) routes them:

| Decision Type | Sou Produces | DGP Routes To |
|--------------|-------------|---------------|
| Strategic | Organizational strategy, priority shifts | Security Council |
| Architectural | System structure proposals | Security Council + Architecture Review |
| Constitutional | Law interpretation proposals | Sou + Security Council |
| Operational | Mission proposals within authority | Entity itself |
| Emergency | Immediate action recommendations | Security Council |

## Sou Components

| Component | Document | Function |
|-----------|----------|----------|
| Reasoning | Sou/001-Reasoning.md | Goal-driven reasoning, decision trees, configuration space search |
| Planner | Sou/002-Planner.md | Mission planning, action sequencing, resource-aware planning |
| Missions | Sou/003-Missions.md | Mission lifecycle oversight from Sou's perspective |
| Learning | Sou/004-Learning.md | Self-improvement from outcomes, refinement of reasoning |
| Knowledge | Sou/005-Knowledge.md | Constitutional memory, private knowledge store |

## Invariants — Sou Operations

1. **Non-Execution Invariant**: Sou never executes actions. All Sou outputs are proposals routed through DGP. Law 2 (Non-Execution) is absolute. (CPR-001, PHI-003)

2. **Evidence-Driven Reasoning**: Every reasoning step, proposal, and learning update produces an Event. Nothing Sou does is invisible. (PHI-002, PHI-008, CPR-004)

3. **Constitutional Bounds**: All Sou operations are bounded by constitutional constraints. Sou cannot propose actions that violate a Law. (CPR-009)

4. **Privacy Preservation**: Sou's knowledge is private by default. It is shared only through Academy channels under CPR-010. (CPR-010)

5. **Learning Integrity**: Sou learns only from evidence. Learning is bounded by laws (CPR-009), evidenced (PHI-008), and privacy-preserving (CPR-010). (PHI-006)

## Edge Cases — Sou Operations

| Scenario | Handling |
|----------|----------|
| Reasoning cannot reach a conclusion | Sou produces "Inconclusive" report with evidence gaps identified. No proposal is sent to DGP. |
| Planner cannot find a feasible plan | Sou reports infeasibility to Reasoning. Reasoning may adjust goal constraints. |
| Learning receives conflicting evidence | Evidence is weighted by source trust score. Lower-trust evidence is deprioritized. |
| Knowledge store is unavailable | Sou operates with degraded reasoning — no knowledge queries, only evidence-based reasoning. |
| DGP is unavailable | Sou queues proposals. If DGP remains unavailable beyond TTL, Sou alerts Security Council. |
| Academy is unavailable for learning | Learning continues with mission and decision outcomes only. Academy knowledge is skipped. |
| Mission evidence is incomplete | Sou evaluates with available evidence, notes gaps, and adjusts confidence accordingly. |
| Entity trust score is stale | DTS decays trust scores over time. Stale scores approach 0.3 (default minimum). |
| Sovereign override in progress | All Sou operations check for Human Override status. If active, proposals are flagged accordingly. |

## Sou Internal Communication Flow

```
1. External event arrives via ACF (e.g., new goal from User)
2. Reasoning ingests event, produces analysis
3. Reasoning passes goal to Planner
4. Planner produces mission plan
5. Missions component packages plan as proposal
6. Proposal sent to DGP via ACF
7. Outcome event arrives (decision approved/rejected)
8. Learning ingests outcome
9. Knowledge stores lessons learned
```

## Sou Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.ReasoningStep` | Sou performs a reasoning step | reason_id, method, input_context, output_proposal |
| `Sou.DecisionProposed` | Sou proposes a decision to DGP | decision_id, decision_type, proposal_body, evidence_chain |
| `Sou.MissionProposed` | Sou proposes a new mission | mission_id, goal, resource_estimate, constitutional_check |
| `Sou.LearningIngested` | Sou ingests an outcome for learning | outcome_id, source_type, evidence_hash |
| `Sou.KnowledgeStored` | Sou stores knowledge | knowledge_id, knowledge_type, privacy_level |
| `Sou.KnowledgeQueried` | Sou queries its knowledge store | query_id, query_type, result_count |

## Cross-Cutting Concerns

### Security

Sou does not execute — it proposes. All Sou proposals are verified by DGP and authorized by the Security Council. Sou's knowledge store is access-controlled. Only authorized entities may query Sou's private knowledge.

### Evidence

Every Sou operation produces an Event. Reasoning steps, proposals, learning updates, and knowledge operations are all recorded. Sou's Event stream is the constitutional record of AIOS strategic intent. (PHI-008, CPR-004)

### Lifecycle

Sou has no operational lifecycle — it is a permanent core engine. However, Sou's proposals (decisions, missions) follow the canonical lifecycle: Proposed → Routed → Approved → Implemented → Verified. (Physics/006-Lifecycles.md)

### Capability Bounds

Sou's capabilities are bounded: it may reason, plan, propose, learn, and store knowledge. It may NOT execute, allocate resources, or communicate outside ACF. (Physics/007-Capabilities.md, PHI-007)

### Communication

All Sou communication flows through ACF. Sou communicates with: DGP (decision proposals), Academy (knowledge sharing), OSYS (organization strategy), and LMS (mission oversight). Law 3 (Law of Communication) applies.

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Sou is focused solely on strategic will — reasoning, planning, learning, knowledge |
| R3 (DRY) | Reasoning patterns are captured in Knowledge, not duplicated across reasoning passes |
| R5 (Liskov) | Planner, Reasoning, Missions, Learning, Knowledge all implement the SouEngine interface |
| R6 (DI) | Sou receives dependencies (Academy, DGP, ACF) through injection |
| R10 (Simpler Over Complex) | Sou's reasoning uses the simplest viable method for each decision type |
| R12 (Embrace Errors) | Every error code is unique and documented |
| R13 (Design for Failure) | Knowledge store has degraded read capability during store unavailability |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 2 (Non-Execution), Law 4 (Evidence) govern Sou |
| Physics/005-Events.md | Sou produces Events for every operation |
| Physics/006-Lifecycles.md | Mission lifecycle — Sou proposes and monitors |
| Physics/007-Capabilities.md | Sou capability bounds — what Sou may and may not do |
| Physics/012-Experience.md | Sou learns from experience evidence |
| Bible/01-Governance/002-DGP.md | DGP routes Sou's decision proposals |
| Bible/01-Governance/003-CRP.md | CRP governs changes to Sou specification |
| Bible/02-Core/Sou/001-Reasoning.md | Sou reasoning engine |
| Bible/02-Core/Sou/002-Planner.md | Sou planning engine |
| Bible/02-Core/Sou/003-Missions.md | Sou mission oversight |
| Bible/02-Core/Sou/004-Learning.md | Sou learning mechanism |
| Bible/02-Core/Sou/005-Knowledge.md | Sou knowledge store |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
