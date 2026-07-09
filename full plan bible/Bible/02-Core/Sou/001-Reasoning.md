# AIOS Bible — Core
## Sou 001 — Reasoning Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-SOU-001 |
| Source Laws | Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou's Reasoning engine is the constitutional decision-making core of AIOS. It evaluates situations, explores decision trees, searches configuration spaces, and produces reasoned proposals. Reasoning transforms evidence and goals into actionable strategic recommendations bounded by constitutional constraints.

Reasoning does not execute — it proposes. All reasoning outputs are routed through DGP (Governance/002-DGP.md) for approval and routing.

## Reasoning Methods

Sou employs four reasoning methods, selected based on the problem domain and available evidence:

### Goal-Directed Reasoning

Used for: strategic planning, mission scoping, resource prioritization.

Goal-directed reasoning works backward from a desired goal state to identify required actions, resources, and dependencies. It produces a goal tree where each sub-goal must be satisfied for the parent goal to succeed.

| Input | Output |
|-------|--------|
| Goal description, current state, success criteria | Goal tree, milestone sequence, resource requirements |
| Constraints, entity capabilities | Feasibility assessment, risk factors |

### Constraint-Based Reasoning

Used for: policy compliance checking, constitutional interpretation, resource-bound planning.

Constraint-based reasons evaluates options within a bounded configuration space defined by constitutional constraints, capability bounds, and resource availability. It identifies feasible regions and eliminates invalid options.

| Input | Output |
|-------|--------|
| Option set, constraint set (constitutional, capability, resource) | Feasibility matrix, constraint violations, recommended options |
| Entity autonomy level (L0–L4) | Autonomy-appropriate option rankings |

### Evidence-Based Reasoning

Used for: learning from outcomes, evaluating past decisions, assessing entity performance.

Evidence-based reasoning consumes Events (Physics/005-Events.md) and Experience (Physics/012-Experience.md) to evaluate the likely outcomes of proposed actions. It quantifies uncertainty and produces confidence estimates.

| Input | Output |
|-------|--------|
| Evidence Events (historical outcomes), current proposal | Outcome prediction, confidence interval, evidence gaps |
| Entity performance history | Trust-weighted recommendation, risk assessment |

### Constitutional Reasoning

Used for: interpretation of constitutional constraints, policy compliance verification, ethical boundary assessment.

Constitutional reasons evaluates proposals against the AIOS Constitution (PHI-001), Core Principles (CPR-001–010), and Design DNA rules (R1–R15). It is the highest-priority reasoning method — constitutional constraints cannot be overridden by other reasoning methods.

| Input | Output |
|-------|--------|
| Proposal, constitutional text, precedent interpretations | Constitutional compliance score, violation list, remediation suggestions |
| Ambiguous governance situation | Interpretation request to DGP for constitutional clarification |

## Reasoning Example

```
Input Situation: User requests "optimize resource allocation across all Workers"
Goal: Produce strategic recommendation for resource reallocation

Reasoning Steps:
1. Evidence-Based: Query Event Store for resource utilization Events (last 30 days)
   → Found: Worker-A 80% utilization, Worker-B 30% utilization, Worker-C 95% utilization

2. Constraint-Based: Evaluate against capability bounds and policies
   → Constraint: Workers cannot exceed 100% utilization (Law 5)
   → Constraint: Worker reallocation requires Security Council approval

3. Goal-Directed: Determine optimal allocation
   → Option 1: Reallocate Worker-B capacity to Worker-C (high impact, high risk)
   → Option 2: Scale down Worker-B, scale up Worker-C (medium impact, low risk)
   → Option 3: Maintain current allocation (no impact, no risk)

4. Constitutional: Verify options against constitutional constraints
   → All options comply — no Law violations

Output: DecisionProposal recommending Option 2 with confidence 0.82
```

## Reasoning Outputs

All reasoning produces structured outputs:

| Output | Description | Routed To |
|--------|-------------|-----------|
| Decision Proposal | A strategic decision with evidence chain, constitutional analysis, and confidence score | DGP (Governance/002-DGP.md) |
| Mission Proposal | A proposed mission with goal, milestones, resource estimates, and constitutional check | DGP → OSYS |
| Strategic Recommendation | Advisory output for existing missions or organizations | Sou Knowledge store, ACF to OSYS |
| Analysis Report | Situation analysis, option evaluation, risk assessment | Sou Knowledge store |

## Reasoning Bounds

Sou's reasoning is bounded by four constraints:

| Bound | Description | Enforcement |
|-------|-------------|-------------|
| Constitutional Constraints | No proposal may violate a Law or constitutional principle | Constitutional reasoning check (mandatory) |
| Capability Bounds | Proposals must respect entity capability assignments (Physics/007-Capabilities.md) | Capability registry query before proposal |
| Available Evidence | Proposals must be supported by evidence (PHI-008) | Evidence chain validation |
| Entity Autonomy Level | Proposals must respect the autonomy level (L0–L4) of affected entities (PHI-003) | Autonomy registry check before proposal |

## Reasoning Operations

### proposeDecision

```
Input:  situation_context, goal, evidence_chain, constraint_set
Process: apply reasoning methods → evaluate options → constitutionally validate
Output: DecisionProposal { decision_id, type, summary, evidence, confidence, constitutional_check }
Routed: DGP.DecisionProposed Event → DGP
```

### analyzeSituation

```
Input:  situation_context, available_evidence
Process: gather evidence → identify patterns → assess risks → produce analysis
Output: AnalysisReport { analysis_id, findings, risks, recommendations }
Stored: Sou Knowledge store
```

### evaluateOptions

```
Input:  option_set, criteria, constraints
Process: score each option → rank → filter invalid → produce ranked list
Output: EvaluatedOptions { evaluation_id, ranked_options, scores, tradeoffs }
Stored: Sou Knowledge store (temporary, used by Planner)
```

## Reasoning Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.ReasoningStarted` | Reasoning session begins | reason_id, method, input_summary |
| `Sou.ReasoningCompleted` | Reasoning session ends | reason_id, output_type, output_id, confidence |
| `Sou.ReasoningFailed` | Reasoning encounters an error | reason_id, error_code, error_message |
| `Sou.DecisionProposed` | proposeDecision succeeds | decision_id, decision_type, constitutional_score |
| `Sou.ReasoningConstraintViolation` | A constraint blocks the proposal | reason_id, constraint_type, violation_details |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| SOU_RSN_001 | Insufficient evidence for reasoning method |
| SOU_RSN_002 | Constitutional constraint violation — proposal blocked |
| SOU_RSN_003 | Circular reasoning dependency detected |
| SOU_RSN_004 | Reasoning method not applicable to problem domain |
| SOU_RSN_005 | Evidence chain incomplete — missing causal link |

## Cross-Cutting Concerns

### Security

Reasoning outputs are proposals, not commands. The Security Council verifies all proposals before execution. Reasoning audits are accessible to the Security Council. (Physics/008-Security.md)

### Evidence

Every reasoning step produces an Event. Reasoning without evidence is prohibited (PHI-008). Evidence chains are validated before proposals are submitted. (Physics/005-Events.md)

### Lifecycle

Reasoning sessions have a defined lifecycle: Initiated → Processing → Completed / Failed. Each session is tracked by LMS. (Physics/006-Lifecycles.md)

### Capability Bounds

Reasoning is bounded by Sou's capabilities. It may reason about any domain but may NOT produce executable code, allocate resources, or bypass governance. (Physics/007-Capabilities.md)

### Communication

Reasoning outputs are communicated via ACF. DGP receives decision proposals. Academy receives learning-related analysis requests. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Reasoning is focused solely on producing reasoned proposals |
| R5 (Liskov) | All reasoning methods implement the Reasoner interface |
| R10 (Simpler Over Complex) | Simplest adequate reasoning method is selected first |
| R12 (Embrace Errors) | All errors have unique codes (SOU_RSN_001–005) |
| R13 (Design for Failure) | Reasoning degrades gracefully when evidence is unavailable |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — reasoning consumes and produces Events |
| Physics/007-Capabilities.md | Capability bounds — reasoning constrained by capabilities |
| Physics/012-Experience.md | Experience — reasoning learns from past outcomes |
| Bible/01-Governance/002-DGP.md | DGP — reasoning proposals are routed through DGP |
| Bible/02-Core/Sou/000-Overview.md | Sou overview — reasoning is the front door of Sou |
| Bible/02-Core/Sou/002-Planner.md | Planner — reasoning feeds planning |
| Bible/02-Core/Sou/004-Learning.md | Learning — reasoning improves from learning |
| Bible/02-Core/Sou/005-Knowledge.md | Knowledge — reasoning reads and writes knowledge |
| Bible/02-Core/DTS/004-Confidence.md | Confidence scoring — reasoning produces confidence estimates |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
