# AIOS Bible — Brain
## 002 — Planning (Delegated to Planning System)

| Property | Value |
|----------|-------|
| Status | Active — updated for new paradigm |
| Version | 2.0 |
| Category | Bible — Brain |
| Document ID | AIOS-BBL-002-SOU-002 |
| Source Laws | Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md, Physics/004-Sessions.md |
| Supersedes | Bible/02-Core/Sou/002-Planner.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou plans by framing goals and delegating decomposition to the **Planning System** — a Brain service that handles strategic and tactical planning, goal decomposition, and milestone tracking. Sou defines what success looks like; the Planning System produces the how.

Planning is resource-aware, constitutionally-compliant, and evidence-driven. Sou retains approval authority over all plans. Execution is delegated through OSYS to Workers.

## Planning Inputs and Outputs

```
┌──────────────┐  goal                    ┌──────────────┐
│  Reasoning   │───────resources─────────▶│   Planner    │
│  (001)       │───constitutional_constraints  (002)    │
│              │───current_state─────────▶│              │
└──────────────┘                          └──────┬───────┘
                                                  │
                                                  ▼
                                          ┌──────────────┐
                                          │ Mission Plan │
                                          └──────────────┘
```

| Input | Source | Description |
|-------|--------|-------------|
| Goal | Reasoning | The desired outcome with success criteria |
| Available Resources | ROS (Resource Orchestration System) | Capabilities, compute, storage, network |
| Constitutional Constraints | Constitution, CPR-001–010 | Legal bounds on what may be planned |
| Current State | LMS (Lifecycle Management) | State of entities that will execute the plan |
| Evidence | Experience (Physics/012-Experience.md) | Historical data on similar plans |

| Output | Destination | Description |
|--------|-------------|-------------|
| Mission Plan | DGP | Structured plan with milestones, resources, timeline, risks |

## Plan Structure

Every mission plan produced by the Planner has the following structure:

| Field | Type | Description |
|-------|------|-------------|
| mission_id | UUID | Unique identifier assigned by Sou |
| goal | Goal | The goal this plan satisfies |
| milestones | Milestone[] | Ordered milestones with acceptance criteria |
| resource_requirements | ResourceMap | Required capabilities, compute, storage, network |
| dependencies | Dependency[] | Prerequisite plans or external conditions |
| timeline | Timeline | Estimated duration for each phase |
| risk_assessment | RiskAssessment | Identified risks with mitigation strategies |
| constitutional_check | ComplianceReport | Evidence of constitutional compliance (CPR-009) |
| evidence_chain | EvidenceRef[] | Supporting evidence Events |
| parent_decision_id | UUID | The decision proposal that triggered this plan |

### Milestone Structure

| Field | Type | Description |
|-------|------|-------------|
| milestone_id | UUID | Unique identifier |
| description | string | What this milestone achieves |
| acceptance_criteria | Criterion[] | Measurable conditions for completion |
| estimated_duration | Duration | Time estimate for this milestone |
| dependencies | UUID[] | Milestones that must precede this one |
| assigned_to | EntityRef | Proposed executing entity or role |

## Planning Operations

### createPlan

```
Input:  goal, resources, constraints, current_state, evidence
Process: 
  1. Analyze goal structure → decompose into milestones
  2. Map milestones to resource requirements
  3. Check resource availability via ROS
  4. Validate constitutional compliance (CPR-009)
  5. Assess risks and produce mitigations
  6. Estimate timeline
Output: MissionPlan
Event: Sou.PlanCreated { plan_id, goal_summary }
```

### refinePlan

```
Input:  plan_id, feedback (from DGP, Security Council, or simulation)
Process:
  1. Identify plan elements requiring refinement
  2. Adjust milestones, resources, or timeline
  3. Re-validate constitutional compliance
  4. Re-assess risks
Output: RefinedMissionPlan
Event: Sou.PlanRefined { plan_id, changes }
```

### validatePlan

```
Input:  plan
Process:
  1. Constitutional compliance check (CPR-009)
  2. Resource feasibility check (ROS integration)
  3. Capability availability check (CCA / Physics/007-Capabilities.md)
  4. Timeline realism check (historical evidence)
  5. Dependency completeness check
Output: ValidationReport { passed: bool, issues: ValidationIssue[] }
```

### compareScenarios

```
Input:  plan_a, plan_b, criteria
Process:
  1. Score each plan against criteria
  2. Identify trade-offs
  3. Produce comparison matrix
Output: ScenarioComparison { recommended: plan_id, matrix, rationale }
```

## Planning Example

```
Input:   "Reduce average mission completion time by 20% within 30 days"
Resources: Available: 10 Workers, 500 compute hours, 1TB storage
Constraints: No Worker may exceed 40h/week (constitutional policy)
Current State: Average completion: 48h, Resource utilization: 60%
Evidence: Historical 15% reduction achieved in Q2 with resource optimization

Planner Output:
  Goal: Reduce avg completion from 48h to 38.4h
  Milestones:
    M1: Resource audit and optimization (Days 1-5)
    M2: Worker retraining on optimized workflows (Days 6-10)
    M3: Parallel execution rollout (Days 11-20)
    M4: Monitoring and adjustment (Days 21-30)
  Resources: 8 Workers (M1-M2), 10 Workers (M3-M4), 300 compute hours
  Risks:
    - Worker burnout if optimization is too aggressive → Mitigation: phased rollout
    - Underestimated training time → Mitigation: buffer 2 days
  Validation:
    - Constitutional: ✓ (Law 5 compliance)
    - Resource feasibility: ✓ (resource plan within limits)
    - Timeline realism: ✓ (similar to Q2 improvement)
```

## Plan Validation

Every plan must pass four validation gates before it can be proposed:

| Gate | Check | Integration |
|------|-------|-------------|
| Constitutional Compliance (CPR-009) | No plan element violates a Law or constitutional principle | Security Council verification |
| Resource Feasibility (ROS) | Required resources exist and are allocatable | ROS registry query |
| Capability Availability (CCA) | Required capabilities are granted to executing entities | Capability Registry (Physics/007-Capabilities.md) |
| Timeline Realism | Estimated duration is consistent with historical evidence | Experience store (Physics/012-Experience.md) |

## Edge Cases — Planner

| Scenario | Handling |
|----------|----------|
| ROS unavailable for resource feasibility check | Planner uses cached resource data (max 5 minutes stale). If no cache, plan proceeds with conservative estimates. |
| Goal changes after plan is created | Planner produces a new plan version. Old plan is archived. Comparison of old vs new is available. |
| All resources are exhausted | Planner returns infeasibility. Suggests: wait for resource release, reduce scope, or request emergency allocation. |
| Timeline estimate exceeds historical bounds | Warning produced. Planner may still create the plan but flags timeline as high-risk. |
| Circular milestone dependency detected | Rejected with SOU_PLN_004. Planner suggests breaking the cycle by reordering or parallelizing. |
| Constitutional constraint is ambiguous | Planner flags constraint as ambiguous. Proceeds with interpretation documented in the plan. |
| Plan validation passes but timeline is unrealistic | Warning produced. Plan is created but tagged for monitoring. DTS simulates it at low confidence. |

## Planner Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.PlanCreated` | A new plan is created | plan_id, goal_id, milestone_count |
| `Sou.PlanRefined` | An existing plan is refined | plan_id, change_summary |
| `Sou.PlanValidated` | Plan passes validation | plan_id, validation_report |
| `Sou.PlanRejected` | Plan fails validation | plan_id, rejection_reason, error_code |
| `Sou.ScenarioCompared` | Two scenarios are compared | comparison_id, plan_a, plan_b, recommendation |
| `Sou.PlanSubmittedToDGP` | Plan is submitted as a mission proposal | plan_id, dgp_ticket_id |

## Error Cases

| Condition | Error Code | Severity | Recovery |
|-----------|------------|----------|----------|
| Goal is underspecified — missing success criteria | SOU_PLN_001 | Medium | Request clarification from goal source; use conservative assumptions |
| Resource requirements exceed available capacity | SOU_PLN_002 | High | Reduce scope, wait for resource release, or request emergency allocation |
| Constitutional constraint violation in plan | SOU_PLN_003 | Critical | Block plan; document violation for Security Council review |
| Circular milestone dependency detected | SOU_PLN_004 | High | Break cycle by reordering or parallelizing milestones |
| Timeline estimate outside historical bounds | SOU_PLN_005 | Low | Flag as high-risk; proceed with monitoring tag |
| Plan validation failed — multiple violations | SOU_PLN_006 | Critical | Return full violation report; require re-plan from corrected inputs |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-PLN-001 | Planner never allocates resources or assigns entities | Architectural — resource checks are queries only |
| SOU-PLN-002 | Every plan must pass all four validation gates before proposal | Algorithmic — gated plan submission pipeline |
| SOU-PLN-003 | Plans always trace to a specific goal from Reasoning | Schema — goal_id required in MissionPlan |
| SOU-PLN-004 | Plan modifications produce a new version, never mutate in place | API-level — refinePlan produces new version |

## Cross-Cutting Concerns

### Security

Plans contain strategic information. Access is controlled by the Security Council. Plan proposals are submitted only through DGP. (Physics/008-Security.md)

### Evidence

Every planning operation produces Events. Plans are derived from evidence (historical outcomes, capability states, resource availability). Evidence chains are preserved in the plan structure. (PHI-008)

### Lifecycle

Plans follow the mission lifecycle: Created (Planner) → Proposed (DGP) → Approved (Security Council) → Executed (OSYS). (Physics/006-Lifecycles.md)

### Capability Bounds

Planner is bounded by Sou's capabilities. It may plan any mission but may NOT allocate resources or assign entities. Resource checks are queries, not allocations. (Physics/007-Capabilities.md)

### Communication

Plans are communicated via ACF. ROS is queried for resource availability. DGP receives plan proposals. LMS receives lifecycle queries. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 — Modulsingularity | Planner focuses solely on mission planning |
| R2 — Dependency Order | Planner depends on Reasoning, ROS, LMS; no upward dependencies |
| R3 — DRY | Plan structure is defined once in the Data Model |
| R4 — Builder Pattern | Plan construction (createPlan) is separate from execution |
| R5 — Liskov Substitution | All planning algorithms implement the Planner interface |
| R6 — DI over Singletons | ROS and LMS clients are injected dependencies |
| R9 — Deterministic | Same goal and constraints produce the same plan structure |
| R10 — Simpler Over Complex | Plans use the simplest sufficient milestone decomposition |
| R13 — Design for Failure | Planner degrades gracefully when ROS is unavailable |
| R14 — Paved Path | All plans flow through createPlan → validatePlan → DGP |
| R15 — Open/Closed | New planning heuristics added by extending, not modifying, the Planner interface |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/004-Sessions.md | Sessions — plans may target specific session types |
| Physics/005-Events.md | Evidence — planning produces and consumes Events |
| Physics/006-Lifecycles.md | Lifecycles — plans are lifecycle-aware |
| Physics/007-Capabilities.md | Capabilities — plans require capability checks |
| Bible/01-Governance/002-DGP.md | DGP — plans are submitted as proposals through DGP |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou overview — planning is a capability of the executive intelligence |
| Bible/02-Core/Brain/Sou/001-Reasoning.md | Reasoning — Planning consumes Reasoning outputs |
| Bible/02-Core/Brain/Sou/003-Missions.md | Missions — Planning produces mission proposals |
| Bible/02-Core/Brain/Sou/004-Learning.md | Learning — Planning improves from learning |
| Bible/02-Core/Brain/Planning/000-Overview.md | Planning System — handles goal decomposition and milestone tracking |
| Bible/02-Core/OSYS | OSYS — plans are executed by Organizations |
| Bible/02-Core/DTS/002-Sim-Pipeline.md | Simulation — plans can be simulated before execution |
| Bible/02-Core/ROS | ROS — resource queries for feasibility checks |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
