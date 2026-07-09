# AIOS Bible — Core
## Sou 003 — Missions

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-SOU-003 |
| Source Laws | Law 1 — Law of Origin, Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou's Missions component oversees the mission lifecycle from Sou's constitutional perspective. Sou proposes missions, monitors their progress, adjusts them as needed, and learns from their outcomes. Missions are the mechanism through which Sou's strategic plans become operational reality.

Sou does not execute missions. It proposes them (DGP routes), Organization approves and owns them, LMS manages their lifecycle, and Workers execute them. Sou observes and learns.

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

## Mission Monitoring

Sou performs routine monitoring of active missions:

| Monitor Check | Frequency | Action on Deviation |
|---------------|-----------|---------------------|
| Progress vs milestones | Daily | If >20% deviation → propose adjustment |
| Resource consumption vs plan | Weekly | If >30% deviation → propose resource reallocation |
| Timeline adherence | Per milestone | If >2 days late → assess impact |
| Risk indicators | Continuous | If risk materializes → propose mitigation |
| Constitutional compliance | Continuous | If violation → alert Security Council |

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

## Sou's Mission Events

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

## Error Codes (R12)

| Code | Description |
|------|-------------|
| SOU_MIS_001 | Mission proposal missing required evidence chain |
| SOU_MIS_002 | Mission goal does not derive from Human Intent (Law 1 violation) |
| SOU_MIS_003 | Cannot adjust mission in terminal state (Completed / Archived) |
| SOU_MIS_004 | Mission outcome evaluation missing completion evidence |
| SOU_MIS_005 | Mission monitor detects unrecoverable state |

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

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Missions component focuses solely on mission lifecycle oversight |
| R3 (DRY) | Mission patterns are captured in Knowledge, not hardcoded |
| R5 (Liskov) | Mission operations implement the MissionOversight interface |
| R10 (Simpler Over Complex) | Mission oversight uses the simplest valid supervision strategy |
| R12 (Embrace Errors) | All errors have unique codes (SOU_MIS_001–005) |
| R13 (Design for Failure) | Sou monitors missions but does not block on failure — alternative proposals |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/002-Missions.md | Mission Physics — canonical mission definitions |
| Physics/005-Events.md | Evidence — Sou consumes mission Events |
| Physics/006-Lifecycles.md | Lifecycle — mission lifecycle states and transitions |
| Physics/012-Experience.md | Experience — Sou learns from mission outcomes |
| Bible/01-Governance/002-DGP.md | DGP — Sou submits mission proposals through DGP |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — Sou reasons about mission adjustments |
| Bible/02-Core/Sou/002-Planner.md | Planner — Sou produces mission plans |
| Bible/02-Core/Sou/004-Learning.md | Learning — Sou learns from completed missions |
| Bible/02-Core/OSYS | OSYS — Organizations own and execute missions |
| Bible/02-Core/DTS | DTS — confidence scoring for mission proposals |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Mission lifecycle — detailed mission state machine |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
