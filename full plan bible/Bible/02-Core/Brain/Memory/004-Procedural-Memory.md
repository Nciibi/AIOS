# AIOS Bible â€” Brain
## 004 â€” Procedural Memory

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-004 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Procedural Memory stores learned procedures, skills, behavioral patterns, and operational routines that Sou has acquired through experience or instruction. Unlike Semantic Memory (facts about the world), Procedural Memory captures "how to do things" â€” the sequences, heuristics, and patterns that Sou uses to perform tasks efficiently.

Procedural Memory is the least structured memory type. Items may include freetext procedures, step-by-step guides, decision trees, playbook references, or automation scripts.

## Data Model

### Procedure

```typescript
Procedure {
  procedure_id: string
  name: string
  description: string
  category: "skill" | "routine" | "playbook" | "heuristic" | "template" | "checklist"
  domain: string                 // Which domain this applies to (e.g., "coding", "security")
  content: ProcedureContent
  confidence: number            // 0.0â€“1.0, how reliable this procedure has proven
  success_rate: number          // 0.0â€“1.0, observed success rate
  invocation_count: number      // How many times this procedure has been used
  tags: string[]
  prerequisites: string[]       // Required capabilities or knowledge
  estimated_duration_ms: number
  version: number
  created_at: timestamp
  updated_at: timestamp
  last_used: timestamp
  metadata: {
    source: string              // "academy" | "experience" | "manual" | "template"
    source_episode?: string
    verified: boolean
    requires_approval: boolean  // Does this procedure need Sou approval before use?
    plasticity: number          // 0.0â€“1.0, how adaptable this procedure is
    related_procedures: string[]
  }
}

ProcedureContent {
  format: "steps" | "freetext" | "decision_tree" | "script" | "playbook_ref"
  
  // If format == "steps"
  steps?: ProcedureStep[]
  
  // If format == "freetext"
  text?: string
  
  // If format == "decision_tree"
  decision_tree?: DecisionNode
  
  // If format == "script"
  script?: {
    language: string
    code: string
    parameters: Record<string, ParameterSchema>
  }
  
  // If format == "playbook_ref"
  playbook_ref?: {
    playbook_id: string
    section: string
    parameters?: Record<string, unknown>
  }
}

ProcedureStep {
  step_number: number
  action: string                // Description of what to do
  expected_outcome: string
  duration_estimate_ms: number
  required_tool?: string
  required_capability?: string
  conditional?: {               // If this step has a condition
    condition: string
    if_true: number             // Next step number
    if_false: number
  }
  error_handling: string        // What to do if this step fails
}

DecisionNode {
  question: string
  branches: DecisionBranch[]
  default_branch?: number
}

DecisionBranch {
  condition: string
  label: string
  action: string | DecisionNode  // Can be a terminal action or nested decision
}
```

### Procedure Categories

| Category | Description | Example | TTL |
|----------|-------------|---------|-----|
| skill | Learned capability | "How to deploy a Worker" | Indefinite |
| routine | Repeated operational sequence | "Morning system health check" | Indefinite |
| playbook | Structured response playbook | "Security incident response" | Indefinite |
| heuristic | Rule of thumb | "If deployment fails, check logs first" | 90 days |
| template | Reusable pattern | "Standard Rust project scaffolding" | Indefinite |
| checklist | Verification checklist | "Pre-deployment verification steps" | Indefinite |

## Learning Pipeline

Procedures are acquired through multiple channels:

```
Experience â†’ Episodic Memory â†’ Pattern Extraction â†’ Procedure Candidate
Academy   â†’ Formal Training â†’ Procedure Registration
Manual    â†’ Sou creates procedure explicitly
Template  â†’ Template Registry â†’ Instantiated Procedure
```

### Experience-Based Learning

```
1. Sou performs an action sequence successfully 3+ times
2. Episodic Memory stores the action sequence
3. Academy Pattern Extraction identifies the recurring pattern
4. Pattern is proposed as a Procedure candidate
5. Sou (or Academy) reviews and approves the candidate
6. Candidate becomes a Procedure in Procedural Memory
7. Procedure is tagged with source domain and prerequisites
```

### Success Rate Tracking

Every time a procedure is used, its outcome is tracked:

| Outcome | Effect on success_rate |
|---------|----------------------|
| Success | `+ (1 - success_rate) * 0.1` |
| Failure | `- success_rate * 0.2` |
| Partial | `+ (0.5 - success_rate) * 0.05` |
| Timeout | `- success_rate * 0.15` |

Procedures with `success_rate < 0.3` are flagged for review.
Procedures with `success_rate < 0.1` are deprecated and archived.

## Usage Patterns

### Pattern 1: Routine Execution

```
1. Sou decides to perform system health check
2. Sou queries Procedural Memory: "morning system health check"
3. Returns Procedure with steps:
   Step 1: Check CPU usage â†’ expected: < 80%
   Step 2: Check memory usage â†’ expected: < 85%
   Step 3: Check disk space â†’ expected: > 20% free
   Step 4: Check service status â†’ expected: all running
4. Sou executes each step, recording outcomes
5. If all steps succeed, success_rate is updated
6. If any step fails, follow error_handling for that step
```

### Pattern 2: Playbook Activation

```
1. Security alert: "Unauthorized access detected"
2. Sou queries Procedural Memory: "security incident response"
3. Returns Playbook with decision tree:
   â”Œâ”€â”€ Is it active? â”€â”€ Yes â”€â”€â†’ Contain â†’ Investigate â†’ Remediate
   â”‚                    No  â”€â”€â†’ Investigate â†’ Document
   â””â”€â”€ Severity? â”€â”€ Critical â†’ Escalate to Human immediately
                    High     â†’ Escalate to Security Council
                    Low      â†’ Handle within Sou's authority
4. Sou follows the playbook, navigating decision nodes
5. Outcome recorded for success_rate update
```

### Pattern 3: Template Instantiation

```
1. Sou needs to create a new Rust project
2. Queries Procedural Memory: "Rust project scaffolding"
3. Returns template procedure with parameters:
   Parameters: { project_name: string, features: string[], edition: string }
4. Sou fills parameters: { project_name: "my_crate", features: ["serde"], edition: "2024" }
5. Procedure expands to concrete steps with parameter substitution
6. Sou executes the expanded procedure
```

## Retrieval Optimization

Procedural Memory uses a multi-strategy retrieval approach:

| Strategy | Latency | Best For |
|----------|---------|----------|
| Exact name match | < 1ms | Known procedure names |
| Tag match | < 5ms | Category-based lookup |
| Semantic search | < 100ms | Unfamiliar tasks, natural language queries |
| Context-prefetch | < 50ms | Proactive preloading based on current context |

### Context-Prefetch

The Context System signals Procedural Memory on context changes:

```typescript
// When Sou enters a known context, prefetch relevant procedures
function prefetchForContext(context: ContextWindow): Procedure[] {
  const signals: string[] = []
  
  if (context.active_mission_state) signals.push("mission")
  if (context.user_input?.text) signals.push("user_input")
  if (context.system_signals.length > 0) signals.push("system_alert")
  
  // Query Procedural Memory for procedures matching context signals
  return proceduralMemory.query({
    tags: signals,
    limit: 3,
    sort: "success_rate"
  })
}
```

## Internal Interfaces

```typescript
interface ProceduralMemoryStore {
  store(procedure: Procedure): Procedure
  get(procedure_id: string): Procedure | null
  query(filter: ProceduralQuery): Procedure[]
  update(procedure_id: string, updates: Partial<Procedure>): Procedure
  delete(procedure_id: string): void

  search(text: string, limit: number): ScoredProcedure[]
  prefetch(context_signals: string[]): Procedure[]

  recordOutcome(procedure_id: string, outcome: ProcedureOutcome): void
  flagForReview(procedure_id: string, reason: string): void

  instantiateTemplate(template_id: string, parameters: Record<string, unknown>): Procedure
}

interface ProceduralQuery {
  category?: string
  domain?: string
  tags?: string[]
  prerequisites?: string[]
  confidence_min?: number
  success_rate_min?: number
  requires_approval?: boolean
  limit: number
  offset?: number
  sort: "success_rate" | "confidence" | "last_used" | "invocation_count"
}

interface ScoredProcedure {
  procedure: Procedure
  score: number
  match_type: "name" | "tag" | "semantic" | "prefetch"
}

interface ProcedureOutcome {
  procedure_id: string
  outcome: "success" | "failure" | "partial" | "timeout"
  duration_ms: number
  error?: string
  context_snapshot: string       // Hash of context at execution time
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| MEM.MEMEvent |  procedure_id, name, category, domain | New procedure created |
| MEM.MEMEvent |  procedure_id, version, updated_fields | Procedure content changed |
| MEM.MEMEvent |  procedure_id, category, reason | Procedure removed |
| MEM.MEMEvent |  procedure_id, success_rate_after, duration_ms | Procedure was used |
| MEM.MEMEvent |  procedure_id, outcome, new_success_rate | Outcome recorded |
| MEM.MEMEvent |  procedure_id, reason, current_success_rate | Procedure needs review |
| MEM.MEMEvent |  procedure_id, replacement_id?, reason | Procedure retired |
| MEM.MEMEvent |  template_id, new_procedure_id, parameters | Template expanded |
| MEM.MEMEvent |  context_signals, results_count, latency_ms | Context-based prefetch |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| PM-001 | Every procedure has a category and domain | Schema â€” required on creation |
| PM-002 | Success rate is bounded [0.0, 1.0] | Schema â€” clamped on update |
| PM-003 | Procedures with success_rate < 0.1 are auto-deprecated | Algorithmic â€” checked after every outcome |
| PM-004 | Procedure steps are sequentially ordered | Schema â€” step_number is monotonic |
| PM-005 | Conditional steps must have both if_true and if_false targets | Schema â€” validated on creation |
| PM-006 | Templates require parameter substitution before execution | Algorithmic â€” instantiateTemplate validates all params |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional - Sou's omniscience within Brain. Access control enforced by Memory OS. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Procedure not found | `PM_PROCEDURE_NOT_FOUND` | Return null; suggest similar procedures |
| Missing required parameter in template | `PM_MISSING_PARAMETER` | Return error; list required parameters |
| Step condition targets nonexistent step | `PM_INVALID_CONDITION` | Return error; validation failed |
| Procedure deprecated | `PM_PROCEDURE_DEPRECATED` | Return error with replacement suggestion |
| Semantic search returns no matches | `PM_NO_MATCHES` | Return empty; suggest broader query |
| Prefetch with no context signals | `PM_NO_SIGNALS` | Return empty; not an error |


## Cross-Cutting Concerns

### Security

Memory OS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Memory OS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Memory OS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Memory OS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Procedural Memory handles only how-to knowledge |
| R2 â€” Dependency Order | Depends on Memory OS core, Academy; no upward deps |
| R3 â€” DRY | Procedures stored once; instantiated via templates |
| R4 â€” Builder Pattern | Procedure built by Learning â†’ Extraction â†’ Approval |
| R5 â€” Liskov Substitution | Any ProceduralMemoryStore implements the interface |
| R6 â€” DI over Singletons | Learning pipeline strategies injected |
| R9 â€” Deterministic | Same procedure produces same execution |
| R10 â€” Simpler Over Complex | Clear category system with success tracking |
| R13 â€” Design for Failure | Low success rate â†’ auto-flag for review |
| R14 â€” Paved Path | All procedures flow through store â†’ execute â†’ track |
| R15 â€” Open/Closed | New procedure formats added via content format field |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Memory/000-Overview.md | Procedural Memory is one of 4 memory types |
| Memory/002-Episodic-Memory.md | Behavioral patterns extracted from episodes |
| Memory/003-Semantic-Memory.md | Procedures reference semantic facts as prerequisites |
| Brain/Cognitive/000-Overview.md | Cognitive OS may recommend procedures |
| Brain/Tools/000-Overview.md | Procedures specify required tools |
| Bible/02-Core/Academy/014-KCE.md | Knowledge Construction Engine builds procedures |
| Bible/03-Institutions/Workers/005-Playbook-Manager.md | Worker playbooks stored here |
