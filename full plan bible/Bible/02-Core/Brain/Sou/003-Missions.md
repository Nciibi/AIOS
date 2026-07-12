# AIOS Bible — Brain
## 003 — Missions (Creation and Oversight)

| Property | Value |
|----------|-------|
| Status | Active — updated for new paradigm |
| Version | 2.0 |
| Category | Bible — Brain |
| Document ID | AIOS-BBL-002-SOU-003 |
| Source Laws | Law 1 — Law of Origin, Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/012-Experience.md |
| Supersedes | Bible/02-Core/Sou/003-Missions.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou is the **sole creator of missions** in AIOS. No component outside the Brain can create missions (SOU-002). Sou defines what work needs to be done, frames success criteria, creates the mission, and delegates execution to Institutions (Organizations → Workers).

Sou does not execute missions. It creates them, monitors progress, adjusts scope as needed, and learns from outcomes. Missions are the mechanism through which Sou's strategic intent becomes operational reality.

## Mission Lifecycle — Sou's Perspective

The canonical mission lifecycle (Physics/002-Missions.md, Physics/006-Lifecycles.md) has 10 states:

```
Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived
```

Sou's involvement varies by state:

| State | Sou's Role | Sou Actions |
|-------|-----------|-------------|
| Created | Proposer | Sou creates the mission proposal (via Planner) and submits it to DGP |
| Planned | Approver of plan | Sou reviews and approves the detailed plan before assignment |
| Assigned | Observer | Sou monitors assignment to executing Organization |
| Running | Adjuster | Sou may propose adjustments based on evidence (via Reasoning → new proposals) |
| Waiting | Observer | Sou monitors waiting state and may propose dependency resolution |
| Paused | Observer | Sou monitors pause reasons, may propose resume conditions |
| Blocked | Evaluator | Sou evaluates block reasons, may propose alternative approaches |
| Review | Evaluator | Sou participates in review — evaluates outcomes against goals |
| Completed | Learner | Sou ingests completion evidence for learning |
| Archived | Learner | Sou archives learnings to Knowledge store |

## Mission Flow — Sou to Execution

```
Sou (Reasoning) ──► Sou (Planner) ──► Sou (Missions propose)
       │                                    │
       │                                    ▼
       │                              DGP (routes)
       │                                    │
       │                                    ▼
       │                         Organization (approves)
       │                                    │
       │                                    ▼
       │                              LMS (lifecycle)
       │                                    │
       │                                    ▼
       │                              Workers (execute)
       │                                    │
       ▼                                    ▼
  Sou (Learning) ◄────── Evidence ◄────────┘
```

## Example — Mission Lifecycle from Sou's View

```
1. Created: Sou proposes "Resource Optimization Q3" mission (via Plannner → DGP)
   → DGP routes to Security Council → Security Council approves
2. Planned: Organization develops detailed plan → Sou approves plan
   → Sou: "Plan approved. Conditions: weekly check-ins required."
3. Assigned: Organization assigns Workers → Sou monitors assignment
   → Sou: "All Workers assigned. Proceeding."
4. Running: Workers execute → Sou monitors progress
   → Monitor check: "Progress at 35%, on track."
5. Running → Review: Check-in triggered (per condition)
   → Sou evaluates: "37% done, resources used: 33%. Acceptable variance."
   → Sou: "Approved to continue."
6. Completed: Mission finishes → Sou evaluates outcome
   → Sou: "Goal: optimize resources. Achievement: 92%. Lessons: phased rollout works."
7. Archived: Sou archives learnings → Knowledge: "Q3 optimization lessons"
```

## Sou's Mission Operations

### proposeMission

```
Input:  goal, plan (from Planner), constitutional_check
Process: package as mission proposal → submit to DGP
Output: MissionProposal { mission_id, proposal, evidence_chain }
Event: Sou.MissionProposed
```

### approveMissionPlan

```
Input:  mission_id, detailed_plan (from Organization)
Process: validate plan matches original proposal → approve
Output: Approval { mission_id, approved_plan, conditions }
Event: Sou.MissionPlanApproved
```

### adjustMission

```
Input:  mission_id, adjustment_reason, proposed_changes
Process: reasoning on adjustment → produce change proposal → submit to DGP
Output: ChangeProposal { mission_id, changes, rationale }
Event: Sou.MissionAdjustmentProposed
```

### evaluateMissionOutcome

```
Input:  mission_id, completion_evidence
Process: compare outcome to goals → assess success → extract lessons
Output: OutcomeEvaluation { mission_id, goal_achievement, lessons }
Event: Sou.MissionOutcomeEvaluated
```

## Missions — Relationship to DTS

DTS provides confidence scoring for Sou's mission proposals:

| Sou Mission Action | DTS Input | DTS Output |
|-------------------|-----------|-------------|
| proposeMission | Mission proposal + evidence | Confidence interval for mission success |
| adjustMission | Adjustment proposal + rationale | Confidence that adjustment improves outcome |
| evaluateMissionOutcome | Outcome evidence | Outcome validation (actual vs predicted) |
| monitorMission | Current mission state | Risk score (probability of mission failure) |

Sou uses DTS confidence to decide whether to proceed with a mission proposal or refine it.

## Mission Monitoring

Sou performs routine monitoring of active missions:

| Monitor Check | Frequency | Action on Deviation |
|---------------|-----------|---------------------|
| Progress vs milestones | Daily | If >20% deviation → propose adjustment |
| Resource consumption vs plan | Weekly | If >30% deviation → propose resource reallocation |
| Timeline adherence | Per milestone | If >2 days late → assess impact |
| Risk indicators | Continuous | If risk materializes → propose mitigation |
| Constitutional compliance | Continuous | If violation → alert Security Council |

## Mission Adjustment Criteria

Sou may propose adjustments to missions when specific criteria are met:

| Criterion | Threshold | Adjustment Type |
|-----------|-----------|-----------------|
| Timeline deviation | >20% behind schedule | Extend timeline or reduce scope |
| Resource overconsumption | >30% over budget | Increase budget or reduce scope |
| Risk materialization | New risk probability >60% | Add mitigation milestone |
| Goal change | External change in priority | Re-scope mission objectives |
| Entity failure | Executing entity fails >3 times | Replace executing entity |
| Constitutional violation | Any violation detected | Pause mission, alert Security Council |

## Sou Evidence Consumption from Missions

Sou receives evidence from completed missions through the following flow:

```
Mission Execution → Events → Event Store → ACF Stream → Sou Learning
```

| Evidence Type | Produced By | Consumed By Sou |
|---------------|-------------|-----------------|
| Milestone completion | Organization / Workers | Planner (improve estimates), Learning (update models) |
| Resource consumption | ROS | Planner (refine resource estimation) |
| Errors and failures | Workers / Runtime | Learning (error pattern recognition) |
| Timing data | LMS | Planner (timeline realism updates) |
| Constitutional compliance | Security Council | Knowledge (constitutional precedent) |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.MissionProposed` | Sou creates a mission proposal | mission_id, goal, plan_id |
| `Sou.MissionPlanApproved` | Sou approves the detailed plan | mission_id, approved_by, conditions |
| `Sou.MissionAdjustmentProposed` | Sou proposes a mission change | mission_id, adjustment_type, rationale |
| `Sou.MissionOutcomeEvaluated` | Sou evaluates mission completion | mission_id, goal_achievement_score, lessons |
| `Sou.MissionMonitored` | Sou performs a routine monitor check | mission_id, state, health_score |
| `Sou.MissionInterventionRequested` | Sou requests governance intervention | mission_id, reason, severity |

## Edge Cases — Missions

| Scenario | Handling |
|----------|----------|
| Mission proposal is rejected by DGP | Sou records rejection. Reasoning may adjust goal and re-propose. Rejection evidence is stored in Knowledge. |
| Mission enters Blocked state and cannot be resolved | Sou evaluates available options: adjust mission, replace executing entity, or abort. If abort → propose new plan. |
| Mission completes but evidence is incomplete | Sou evaluates with available evidence. Gaps are noted in outcome evaluation. Confidence is reduced. |
| Sou proposes adjustment while mission is in Review | Adjustment is queued. Review must complete before adjustment is applied. |
| Mission's parent Organization is dissolved | Sou is notified. Sou proposes mission transfer to another Organization or mission termination. |
| Sou receives conflicting evidence from mission | Evidence from different sources is weighted by source trust. Higher-trust source takes precedence. |
| Mission exceeds its planned duration significantly | Sou evaluates cause. May propose scope reduction, resource increase, or mission termination. |

## Error Cases

| Condition | Error Code | Severity | Recovery |
|-----------|------------|----------|----------|
| Mission proposal missing required evidence chain | SOU_MIS_001 | High | Block proposal; require evidence from Reasoning before submission |
| Mission goal does not derive from Human Intent (Law 1 violation) | SOU_MIS_002 | Critical | Reject proposal permanently; log constitutional violation for review |
| Cannot adjust mission in terminal state (Completed / Archived) | SOU_MIS_003 | Medium | Return error; propose new mission if adjustment is necessary |
| Mission outcome evaluation missing completion evidence | SOU_MIS_004 | High | Evaluate with available evidence; mark gaps and reduce confidence |
| Mission monitor detects unrecoverable state | SOU_MIS_005 | Critical | Escalate to Security Council; propose mission termination |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-MIS-001 | Sou is the sole creator of missions in AIOS | Governance — no other component may create missions |
| SOU-MIS-002 | Sou never executes missions — only creates, monitors, and learns | Architectural — no execution path in Sou |
| SOU-MIS-003 | Every mission proposal traces to a Human Intent | Schema — Law 1 evidence chain required |
| SOU-MIS-004 | Mission adjustments are always proposed, never applied directly | API-level — adjustMission produces proposal, not mutation |

## Cross-Cutting Concerns

### Security

Mission proposals are verified by DGP. Organizational approval is required before execution. All Sou mission operations produce Events for audit by the Security Council. (Physics/008-Security.md)

### Evidence

Every mission action produces Events. Sou consumes mission evidence for learning. Evidence chains from Law 1 (Origin) are preserved — every mission traces to Human Intent. (PHI-008, CPR-004)

### Lifecycle

Sou's mission oversight follows the canonical lifecycle (Physics/006-Lifecycles.md). Sou is involved at key transition points: Created (propose), Running (adjust), Completed/Archived (evaluate/learn). (PHI-006)

### Capability Bounds

Sou may propose, monitor, adjust, and evaluate missions. It may NOT approve mission execution, allocate resources to missions, or directly communicate with Workers executing missions. (Physics/007-Capabilities.md)

### Communication

All mission-related communication flows through ACF. DGP receives proposals. OSYS receives strategy. LMS receives lifecycle queries. Academy receives learning evidence. (Law 3 — Communication)

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 — Modulsingularity | Missions component focuses solely on mission lifecycle oversight |
| R2 — Dependency Order | Missions depends on Reasoning, Planner, DGP; no upward dependencies |
| R3 — DRY | Mission patterns are captured in Knowledge, not hardcoded |
| R4 — Builder Pattern | Mission proposals are built through the proposeMission pipeline |
| R5 — Liskov Substitution | Mission operations implement the MissionOversight interface |
| R6 — DI over Singletons | DGP and LMS clients are injected dependencies |
| R9 — Deterministic | Same mission evidence produces the same outcome evaluation |
| R10 — Simpler Over Complex | Mission oversight uses the simplest valid supervision strategy |
| R13 — Design for Failure | Sou monitors missions but does not block on failure — alternative proposals |
| R14 — Paved Path | All missions flow through propose → monitor → evaluate → learn |
| R15 — Open/Closed | New supervision strategies added by extending MissionOversight |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/002-Missions.md | Mission Physics — canonical mission definitions |
| Physics/005-Events.md | Evidence — Sou consumes mission Events |
| Physics/006-Lifecycles.md | Lifecycle — mission lifecycle states and transitions |
| Physics/012-Experience.md | Experience — Sou learns from mission outcomes |
| Bible/01-Governance/002-DGP.md | DGP — Sou submits mission proposals through DGP |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou overview — mission creation is exclusive to Sou |
| Bible/02-Core/Brain/Sou/001-Reasoning.md | Reasoning — Sou reasons about mission adjustments |
| Bible/02-Core/Brain/Sou/002-Planner.md | Planning — Sou produces mission plans via Planning System |
| Bible/02-Core/Brain/Sou/004-Learning.md | Learning — Sou learns from completed missions |
| Bible/02-Core/OSYS | OSYS — Organizations own and execute missions |
| Bible/02-Core/DTS | DTS — confidence scoring for mission proposals |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Mission lifecycle — detailed mission state machine |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
