# AIOS Bible â€” Brain
## 001 â€” Reasoning (Delegated to Cognitive OS)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 2.0.0 |
| Category | Bible â€” Brain |
| Document ID | AIOS-BBL-002-SOU-001 |
| Source Laws | Law 2 â€” Law of Non-Execution, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Bible/02-Core/Sou/001-Reasoning.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou reasons about situations, goals, and strategies by delegating to the **Cognitive OS** â€” a Brain service that implements reasoning, reflection, and metacognition. Sou frames the problem, Cognitive OS executes the reasoning methods, and Sou evaluates the output.

Reasoning does not execute â€” it proposes. All reasoning outputs are routed through DGP (Bible/01-Governance/002-DGP.md) for approval and routing.

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
| Entity autonomy level (L0â€“L4) | Autonomy-appropriate option rankings |

### Evidence-Based Reasoning

Used for: learning from outcomes, evaluating past decisions, assessing entity performance.

Evidence-based reasoning consumes Events (Physics/005-Events.md) and Experience (Physics/012-Experience.md) to evaluate the likely outcomes of proposed actions. It quantifies uncertainty and produces confidence estimates.

| Input | Output |
|-------|--------|
| Evidence Events (historical outcomes), current proposal | Outcome prediction, confidence interval, evidence gaps |
| Entity performance history | Trust-weighted recommendation, risk assessment |

### Constitutional Reasoning

Used for: interpretation of constitutional constraints, policy compliance verification, ethical boundary assessment.

Constitutional reasons evaluates proposals against the AIOS Constitution (PHI-001), Core Principles (CPR-001â€“010), and Design DNA rules (R1â€“R15). It is the highest-priority reasoning method â€” constitutional constraints cannot be overridden by other reasoning methods.

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
   â†’ Found: Worker-A 80% utilization, Worker-B 30% utilization, Worker-C 95% utilization

2. Constraint-Based: Evaluate against capability bounds and policies
   â†’ Constraint: Workers cannot exceed 100% utilization (Law 5)
   â†’ Constraint: Worker reallocation requires Security Council approval

3. Goal-Directed: Determine optimal allocation
   â†’ Option 1: Reallocate Worker-B capacity to Worker-C (high impact, high risk)
   â†’ Option 2: Scale down Worker-B, scale up Worker-C (medium impact, low risk)
   â†’ Option 3: Maintain current allocation (no impact, no risk)

4. Constitutional: Verify options against constitutional constraints
   â†’ All options comply â€” no Law violations

Output: DecisionProposal recommending Option 2 with confidence 0.82
```

## Reasoning Outputs

All reasoning produces structured outputs:

| Output | Description | Routed To |
|--------|-------------|-----------|
| Decision Proposal | A strategic decision with evidence chain, constitutional analysis, and confidence score | DGP (Bible/01-Governance/002-DGP.md) |
| Mission Proposal | A proposed mission with goal, milestones, resource estimates, and constitutional check | DGP â†’ OSYS |
| Strategic Recommendation | Advisory output for existing missions or organizations | Sou Knowledge store, ACF to OSYS |
| Analysis Report | Situation analysis, option evaluation, risk assessment | Sou Knowledge store |

## Reasoning Bounds

Sou's reasoning is bounded by four constraints:

| Bound | Description | Enforcement |
|-------|-------------|-------------|
| Constitutional Constraints | No proposal may violate a Law or constitutional principle | Constitutional reasoning check (mandatory) |
| Capability Bounds | Proposals must respect entity capability assignments (Physics/007-Capabilities.md) | Capability registry query before proposal |
| Available Evidence | Proposals must be supported by evidence (PHI-008) | Evidence chain validation |
| Entity Autonomy Level | Proposals must respect the autonomy level (L0â€“L4) of affected entities (PHI-003) | Autonomy registry check before proposal |

## Reasoning Operations

### proposeDecision

```
Input:  situation_context, goal, evidence_chain, constraint_set
Process: apply reasoning methods â†’ evaluate options â†’ constitutionally validate
Output: DecisionProposal { decision_id, type, summary, evidence, confidence, constitutional_check }
Routed: DGP.DecisionProposed Event â†’ DGP
```

### analyzeSituation

```
Input:  situation_context, available_evidence
Process: gather evidence â†’ identify patterns â†’ assess risks â†’ produce analysis
Output: AnalysisReport { analysis_id, findings, risks, recommendations }
Stored: Sou Knowledge store
```

### evaluateOptions

```
Input:  option_set, criteria, constraints
Process: score each option â†’ rank â†’ filter invalid â†’ produce ranked list
Output: EvaluatedOptions { evaluation_id, ranked_options, scores, tradeoffs }
Stored: Sou Knowledge store (temporary, used by Planner)
```

## Reasoning â€” Relationship to DTS

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

## Events

| SOU.EventType | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.ReasoningStarted` | Reasoning session begins | reason_id, method, input_summary |
| `Sou.ReasoningCompleted` | Reasoning session ends | reason_id, output_type, output_id, confidence |
| `Sou.ReasoningFailed` | Reasoning encounters an error | reason_id, error_code, error_message |
| `Sou.DecisionProposed` | proposeDecision succeeds | decision_id, decision_type, constitutional_score |
| `Sou.ReasoningConstraintViolation` | A constraint blocks the proposal | reason_id, constraint_type, violation_details |

## Edge Cases â€” Reasoning

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

## Error Cases

| Condition | Error Code | Severity | Recovery |
|-----------|------------|----------|----------|
| Insufficient evidence for reasoning method | SOU_RSN_001 | Medium | Fall back to available evidence; flag gaps in output |
| Constitutional constraint violation â€” proposal blocked | SOU_RSN_002 | Critical | Block proposal; require constitutional clarification from DGP |
| Circular reasoning dependency detected | SOU_RSN_003 | High | Break cycle by selecting most authoritative source |
| Reasoning method not applicable to problem domain | SOU_RSN_004 | Medium | Select alternative reasoning method; log method mismatch |
| Evidence chain incomplete â€” missing causal link | SOU_RSN_005 | High | Continue with reduced confidence; flag missing links |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-RSN-001 | Reasoning never produces executable code | Architectural â€” no code execution path |
| SOU-RSN-002 | Every reasoning session produces exactly one proposal or failure event | API-level â€” event emission enforced |
| SOU-RSN-003 | Reasoning output is always reviewed by DGP before execution | Governance â€” DGP pipeline enforcement |
| SOU-RSN-004 | Constitutional reasoning is always applied to every proposal | Algorithmic â€” selectReasoningMethod always includes it |

| BRAIN-002 | Sou is the only component with strategic decision authority. | Constitutional - SOU-001. Verified by Security Council. |
| BRAIN-005 | Every user-facing response passes through Sou. | Constitutional - SOU-005. ACF routing enforced. |
## Cross-Cutting Concerns

### Security

Reasoning outputs are proposals, not commands. The Security Council verifies all proposals before execution. Reasoning audits are accessible to the Security Council. (Physics/008-Security.md)

### Evidence

Every reasoning step produces an Event. Reasoning without evidence is prohibited (PHI-008). Evidence chains are validated before proposals are submitted. (Physics/005-Events.md)

### Lifecycle

Reasoning sessions have a defined lifecycle: Initiated â†’ Processing â†’ Completed / Failed. Each session is tracked by LMS. (Physics/006-Lifecycles.md)

### Capability Bounds

Reasoning is bounded by Sou's capabilities. It may reason about any domain but may NOT produce executable code, allocate resources, or bypass governance. (Physics/007-Capabilities.md)

### Communication

Reasoning outputs are communicated via ACF. DGP receives decision proposals. Academy receives learning-related analysis requests. (Law 3 â€” Communication)

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 â€” Modulsingularity | Reasoning is focused solely on producing reasoned proposals |
| R2 â€” Dependency Order | Reasoning depends on Cognitive OS and DGP; no upward dependencies |
| R3 â€” DRY | Reasoning methods are defined once in the Reasoner interface |
| R4 â€” Builder Pattern | Decision proposals built through the proposeDecision pipeline |
| R5 â€” Liskov Substitution | All reasoning methods implement the Reasoner interface |
| R6 â€” DI over Singletons | Cognitive OS is injected, not a singleton |
| R9 â€” Deterministic | Same evidence and constraints produce the same reasoning output |
| R10 â€” Simpler Over Complex | Simplest adequate reasoning method is selected first |
| R13 â€” Design for Failure | Reasoning degrades gracefully when evidence is unavailable |
| R14 â€” Paved Path | All reasoning flows through proposeDecision â†’ DGP |
| R15 â€” Open/Closed | New reasoning methods added by extending Reasoner, not by modifying existing methods |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence â€” reasoning consumes and produces Events |
| Physics/007-Capabilities.md | Capability bounds â€” reasoning constrained by capabilities |
| Physics/012-Experience.md | Experience â€” reasoning learns from past outcomes |
| Bible/01-Governance/002-DGP.md | DGP â€” reasoning proposals are routed through DGP |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou overview â€” reasoning is a capability of the executive intelligence |
| Bible/02-Core/Brain/Sou/002-Planner.md | Planner â€” reasoning feeds planning |
| Bible/02-Core/Brain/Sou/004-Learning.md | Learning â€” reasoning improves from learning |
| Bible/02-Core/Brain/Sou/005-Knowledge.md | Knowledge â€” reasoning reads and writes knowledge |
| Bible/02-Core/Brain/Context/000-Overview.md | Context System â€” provides context for reasoning |
| Bible/02-Core/DTS/004-Confidence.md | Confidence scoring â€” reasoning produces confidence estimates |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
