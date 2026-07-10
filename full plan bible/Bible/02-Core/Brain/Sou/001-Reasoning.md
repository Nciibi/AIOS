# AIOS Bible — Brain
## Sou 001 — Reasoning (Delegated to Cognitive OS)

| Property | Value |
|----------|-------|
| Status | Active — updated for new paradigm |
| Version | 2.0 |
| Category | Bible — Brain |
| Document ID | AIOS-BBL-002-SOU-001 |
| Source Laws | Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Bible/02-Core/Sou/001-Reasoning.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou reasons about situations, goals, and strategies by delegating to the **Cognitive OS** — a Brain service that implements reasoning, reflection, and metacognition. Sou frames the problem, Cognitive OS executes the reasoning methods, and Sou evaluates the output.

Reasoning does not execute — it proposes. All reasoning outputs are routed through DGP (Governance/002-DGP.md) for approval and routing.

In the new paradigm, reasoning is a **capability** Sou exercises through Cognitive OS, not a module Sou implements internally. This separation keeps Sou focused on identity, goals, and decisions while Cognitive OS provides the reasoning infrastructure.

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

## Reasoning — Relationship to DTS

Sou's Reasoning engine works closely with DTS:

| Step | Sou Reasoning | DTS (Confidence) |
|------|---------------|-------------------|
| Evaluate options | Produces option set with pros/cons | Scores each option with confidence interval |
| Constitutional check | Flags potential violations | Confirms constitutional compliance score |
| Risk assessment | Identifies qualitative risks | Quantifies risk probabilities via simulation |
| Proposal confidence | Internal confidence estimate | Produces evidence-based confidence interval |
| Final recommendation | Ranks options by Sou's judgment | Provides independent confidence score for each option |

Sou Reasoning's output is always combined with DTS confidence before submission to DGP.

## Reasoning Selection Algorithm

```
function selectReasoningMethod(problem, evidence, constraints):
  // Constitutional reasoning is ALWAYS applied
  // Other methods are selected based on problem type

  methods = []
  
  if problem has clear goal state:
    methods.append(GoalDirected)
  
  if problem has well-defined constraints with options:
    methods.append(ConstraintBased)
  
  if sufficient evidence Events exist (>10 relevant):
    methods.append(EvidenceBased)
  
  // Always apply constitutional reasoning
  methods.append(Constitutional)
  
  return methods
```

## Reasoning Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.ReasoningStarted` | Reasoning session begins | reason_id, method, input_summary |
| `Sou.ReasoningCompleted` | Reasoning session ends | reason_id, output_type, output_id, confidence |
| `Sou.ReasoningFailed` | Reasoning encounters an error | reason_id, error_code, error_message |
| `Sou.DecisionProposed` | proposeDecision succeeds | decision_id, decision_type, constitutional_score |
| `Sou.ReasoningConstraintViolation` | A constraint blocks the proposal | reason_id, constraint_type, violation_details |

## Edge Cases — Reasoning

| Scenario | Handling |
|----------|----------|
| Conflicting evidence from equally trusted sources | Reasoning applies consistency weighting. If evidence is irreconcilable, both sides are presented with confidence reduced accordingly. |
| Goal is underspecified | Reasoning requests clarification from goal source. If unavailable, reasoning proceeds with assumptions documented in the output. |
| Constitutional ambiguity | Reasoning flags ambiguous constraints. Decision proposal includes request for constitutional clarification from DGP. |
| Evidence stream interrupted mid-reasoning | Reasoning continues with available evidence. Gaps are noted in output. |
| Reasoning takes too long | Reasoning has configurable time budget (default 30s). Exceeding budget produces partial results with reduced confidence. |
| All reasoning methods fail | Sou produces "Unable to Reason" result with error details. No proposal is generated. |
| Circular reasoning dependency | Dependency cycle detector (SOU_RSN_003) breaks the cycle by selecting the most authoritative source. |
| Entity under Human Override | Reasoning checks override status. If override is active, all proposals are flagged accordingly. |

## Reasoning Performance Requirements

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Time to propose simple decision | < 1 second | 5 seconds |
| Time to propose complex decision | < 5 seconds | 30 seconds |
| Time to analyze situation | < 2 seconds | 10 seconds |
| Time to evaluate options | < 3 seconds | 15 seconds |
| Maximum reasoning depth | 10 levels | 20 levels |
| Maximum options evaluated | 50 options | 100 options |

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
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou overview — reasoning is a capability of the executive intelligence |
| Bible/02-Core/Brain/Sou/002-Planner.md | Planner — reasoning feeds planning |
| Bible/02-Core/Brain/Sou/004-Learning.md | Learning — reasoning improves from learning |
| Bible/02-Core/Brain/Sou/005-Knowledge.md | Knowledge — reasoning reads and writes knowledge |
| Bible/02-Core/Brain/Context/000-Overview.md | Context System — provides context for reasoning |
| Bible/02-Core/DTS/004-Confidence.md | Confidence scoring — reasoning produces confidence estimates |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
