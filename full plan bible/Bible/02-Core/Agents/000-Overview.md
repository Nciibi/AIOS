# AIOS Bible — Core
## AGX 000 — Overview (Agent Evolution System)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core/Agents |
| Document ID | AIOS-BBL-002-AGX-000 |
| Source Laws | Law 6 — Lifecycle Compliance, Law 7 — Capability Bounds, Law 10 — Tenure |
| Source Physics | Physics/007-Capabilities.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Agent Evolution System enables agents to autonomously improve their capabilities, adapt to changing requirements, and progress through defined lifecycle stages. Today you create agents; tomorrow agents should improve themselves. AGX transforms static agent configurations into evolving digital entities that grow more effective over time through performance analysis, genome optimization, and structured promotion.

AGX is the engine of agent growth. It does not create agents (AGS handles genome templates) and does not direct strategic priorities (Sou decides what evolves). AGX answers *how* an agent evolves — the mechanics of performance measurement, genome mutation, certification, promotion, and retirement.

## Architecture

```
                    ┌─────────────────────┐
                    │  Performance Sources │
                    │ Metrics   Failures   │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Performance Analyzer │
                    └──────────┬──────────┘
                               │ Report
                    ┌──────────▼──────────┐
                    │   Evolution Engine  │
                    │  (orchestrator)     │
                    └──┬──────┬──────┬────┘
                       │      │      │
              ┌────────▼─┐ ┌──▼───┐ ┌▼──────────┐
              │  Mutation │ │Cert. │ │ Retirement │
              │  Engine   │ │Auth. │ │  Manager   │
              └────┬─────┘ └──┬───┘ └─────┬──────┘
                   │          │            │
              ┌────▼──────────▼────────────▼──────┐
              │        Genome Repository          │
              │  (versioned agent genome store)   │
              └────────────────┬──────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Competency Registry │
                    │  (tree + lifecycle) │
                    └─────────────────────┘
```

## Core Concepts

### 1. Agent Genome

The complete encoded definition of an agent: capabilities, parameters, playbooks, policies, and bounds. The genome is the unit of evolution — AGX mutates, optimizes, and versions genomes while preserving the agent's identity (Law 5). Every evolution event produces a new genome version, creating a complete ancestry trail.

### 2. Evolution Lifecycle

Agents progress through defined maturity stages: **Nascent → Apprentice → Proficient → Expert → Master**. Each stage unlocks broader capabilities and higher autonomy levels. Promotion is unidirectional — an agent cannot regress to a lower stage.

| Stage | Autonomy | Promotion Requirement |
|-------|----------|-----------------------|
| Nascent | L0 | Basic task completion within bounds |
| Apprentice | L1 | Consistent performance, <5% error rate |
| Proficient | L2 | Autonomy within domain, playbook optimization |
| Expert | L3 | Cross-domain capability, mentoring |
| Master | L4 | Strategic autonomy, capability discovery |

### 3. Competency Tree

A hierarchical, acyclic graph of agent capabilities showing prerequisite chains and advancement paths. Each node represents a competency with required proficiency level, prerequisite competencies, and the capabilities it unlocks. AGX uses the competency tree to determine promotion readiness and identify capability gaps.

### 4. Performance Analysis

Continuous evaluation of agent effectiveness from multiple metrics: task completion rate, quality scores (from Academy evidence), resource efficiency, response latency, error frequency, and user satisfaction. Performance analysis runs on a configurable cadence and produces a structured PerformanceReport used by the Evolution Engine.

### 5. Failure Analysis

Deep analysis of agent failures (from EVS evidence records) to identify root causes, classify failure modes, and determine improvement opportunities. Failures are categorized as transient (network, resource contention), systemic (capability gap, insufficient training), or constitutional (policy violation, authorization denial). Each category triggers a different evolution response.

### 6. Genome Mutation

Algorithmic optimization of agent genome parameters: weight adjustments, threshold tuning, configuration changes. Mutation strategies include gradient-based (minimal change toward performance target), exploratory (random parameter variation within bounds), and guided (Academy-derived optimization candidates).

### 7. Genome Optimization

Structural improvement of the genome beyond parameter tuning: adding new playbooks, restructuring behavior patterns, pruning unused capabilities, upgrading dependency versions. Optimizations are validated in simulation before being committed to the active genome.

### 8. Playbook Optimization

Iterative refinement of agent behavior patterns and decision procedures. AGX analyzes execution traces, identifies suboptimal patterns, and proposes improved playbook variants. The agent adopts the variant that demonstrates superior performance over a validation period.

### 9. Capability Discovery

Agents can identify gaps in their capability set through performance analysis and failure analysis. When a capability gap is detected, AGX queries the Competency Registry for available capabilities that satisfy the gap. New capabilities must be certified by the Certification Authority before the agent can exercise them, ensuring Law 7 (Capability Bounds) compliance.

### 10. Certification

Formal validation gates that agents must pass before promotion to the next lifecycle stage. Certification evaluates: performance metrics (are they consistently above threshold?), competency coverage (are all prerequisites satisfied?), policy compliance (have there been violations?), and simulation results (does the agent perform correctly at the target stage?).

### 11. Retirement

Graceful decommissioning of agents that are no longer effective, whose mission is complete, or who have exceeded tenure (Law 10). Retirement preserves the agent's genome ancestry and evidence trail for auditability. Once retired, an agent cannot be reactivated — a new agent must be created from the retired genome if needed (immutable retirement per AGX-004).

## Data Model

```typescript
interface AgentGenome {
  agentId: string;
  version: number;
  stage: EvolutionStage;
  capabilities: Capability[];
  parameters: Record<string, number>;
  playbooks: Playbook[];
  policies: PolicyBinding[];
  bounds: CapabilityBounds;
  parentGenomeVersion: number | null;
  createdAt: Timestamp;
  evidenceRef: string;
}

interface EvolutionState {
  agentId: string;
  currentStage: EvolutionStage;
  genomeVersion: number;
  certifications: Certification[];
  performanceHistory: PerformanceReport[];
  retirementDate: Timestamp | null;
}

interface PerformanceReport {
  reportId: string;
  agentId: string;
  period: { start: Timestamp; end: Timestamp };
  metrics: {
    taskCompletionRate: number;
    qualityScore: number;
    resourceEfficiency: number;
    avgLatency: number;
    errorRate: number;
    satisfactionScore: number;
  };
  failureSummary: FailureRecord[];
  genomeVersion: number;
}

interface CompetencyNode {
  competencyId: string;
  name: string;
  description: string;
  requiredProficiency: number;
  prerequisites: string[];
  unlocks: string[];
  capabilityReferences: string[];
}

interface CertificationResult {
  certificationId: string;
  agentId: string;
  targetStage: EvolutionStage;
  status: 'pending' | 'passed' | 'failed';
  gates: CertificationGate[];
  evidenceRef: string;
  certifiedAt: Timestamp | null;
}
```

## Interfaces

### AGX API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `analyzeAgentPerformance(agentId)` | Sou, Academy | Trigger performance analysis for an agent |
| `mutateGenome(agentId, strategy)` | Evolution Engine | Apply a mutation strategy to an agent's genome |
| `certifyAgent(agentId, targetStage)` | Sou | Initiate certification process for promotion |
| `promoteAgent(agentId, targetStage)` | Sou, Security Council | Promote agent to next lifecycle stage |
| `retireAgent(agentId, reason)` | Sou, OSYS | Initiate graceful retirement |
| `discoverCapabilities(agentId, domain)` | Agent | Discover capability candidates for a domain |
| `getEvolutionStatus(agentId)` | Any | Return current evolution state |
| `getGenomeHistory(agentId)` | Sou, Security Council | Return version history of agent genome |

### Internal Interfaces

```typescript
interface EvolutionEngine {
  orchestrateEvolution(agentId: string): Promise<EvolutionEvent>;
  evaluatePromotionReadiness(agentId: string): Promise<PromotionReadiness>;
  schedulePerformanceAnalysis(agentId: string, cadence: Duration): void;
}

interface MutationEngine {
  applyParameterMutation(genome: AgentGenome, strategy: MutationStrategy): AgentGenome;
  applyStructuralOptimization(genome: AgentGenome, targets: OptimizationTarget[]): AgentGenome;
  validateMutation(original: AgentGenome, mutated: AgentGenome): ValidationResult;
}

interface CertificationAuthority {
  validateGates(agentId: string, targetStage: EvolutionStage): Promise<CertificationResult>;
  issueCertification(result: CertificationResult): void;
  revokeCertification(agentId: string, reason: string): void;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Evolution Engine | Orchestrates the evolution lifecycle — schedules analysis, triggers mutation, manages promotion gates |
| Genome Repository | Stores, versions, and serves agent genomes; maintains ancestry trail |
| Performance Analyzer | Collects metrics from EVS and ACF, produces structured performance reports |
| Mutation Engine | Applies algorithmic parameter mutations and structural genome optimizations |
| Certification Authority | Validates promotion readiness through multi-gate evaluation |
| Competency Registry | Manages competency tree definitions, prerequisite chains, and capability mappings |
| Retirement Manager | Handles graceful decommissioning, evidence preservation, and lifecycle termination |

## Data Flow

```
Agent completes mission
        │
        ▼
ACF dispatches completion event ──► EVS stores evidence
        │
        ▼
Performance Analyzer collects metrics
        │
        ▼
Evolution Engine evaluates: promote / mutate / retire / noop
        │
        ├── promote ──► Certification Authority ──► Promotion gate ──► Agent promoted
        │
        ├── mutate ──► Mutation Engine ──► Genome Repository ──► New genome version
        │
        ├── retire ──► Retirement Manager ──► Agent decommissioned
        │
        └── noop ──► Schedule next analysis
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `AGX.PerformanceReported` | agentId, reportId, metrics | Performance analysis completed |
| `AGX.GenomeMutated` | agentId, oldVersion, newVersion | Agent genome updated |
| `AGX.CapabilityDiscovered` | agentId, competencyId, capability | New capability discovered by agent |
| `AGX.CertificationRequested` | agentId, targetStage | Promotion certification initiated |
| `AGX.CertificationCompleted` | agentId, targetStage, result | Certification passed or failed |
| `AGX.PromotionCompleted` | agentId, fromStage, toStage | Agent promoted to next lifecycle stage |
| `AGX.RetirementInitiated` | agentId, reason | Agent retirement started |
| `AGX.RetirementCompleted` | agentId, genomeVersion | Agent retired successfully |
| `AGX.CapabilityGapDetected` | agentId, gapDescription | Performance analysis detected a capability gap |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Agent not registered with IDS/AGS | `AGX_UNKNOWN_AGENT` | Reject operation; agent must exist first |
| Performance below promotion threshold | `AGX_INSUFFICIENT_PERFORMANCE` | Deny certification; schedule performance improvement |
| Certification gate validation failed | `AGX_CERTIFICATION_FAILED` | Deny promotion; return gate failure details |
| Genome data integrity check failed | `AGX_GENOME_CORRUPT` | Lock genome; notify Security Council |
| Missing prerequisite competencies | `AGX_COMPETENCY_GAP` | Deny promotion; recommend competency acquisition path |
| Agent already undergoing retirement | `AGX_RETIREMENT_IN_PROGRESS` | Reject new operations; wait for retirement completion |
| Mutation would exceed capability bounds | `AGX_MUTATION_OUT_OF_BOUNDS` | Reject mutation; bounds are immutable per Law 7 |
| Agent at maximum evolution stage | `AGX_ALREADY_MAX_STAGE` | Return current stage; no further promotion possible |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| AGX-001 | Every agent has exactly one active genome version at any time | Architectural — Genome Repository enforces single active version |
| AGX-002 | Promotion is unidirectional — agents cannot demote to a lower stage | Algorithmic — stage transition table permits only forward moves |
| AGX-003 | Certification requires passing all evaluation gates in sequence | Algorithmic — gate sequence cannot be skipped |
| AGX-004 | Retirement is permanent — retired agents cannot be reactivated | Architectural — retired genomes are immutable; new agent must be created |
| AGX-005 | Every genome mutation produces a versioned, auditable record | Architectural — Genome Repository creates new version on every mutation |
| AGX-006 | Competency trees form a directed acyclic graph | Algorithmic — cycle detection on tree registration |
| AGX-007 | No agent may be promoted beyond L4 (Master) | Constitutional — Law 10 ensures all agents are bounded |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | AGX owns agent evolution exclusively; AGS owns genome creation; Sou owns strategic direction |
| R2 — Dependency Order | AGX depends on AGS (genomes), Academy (learning data), EVS (evidence); no circular dependencies |
| R3 — DRY | Evolution lifecycle is defined once in the stage transition table; agents reference, not duplicate |
| R4 — Builder Pattern | Genome mutation and certification result use builder construction for complex validation chains |
| R9 — Deterministic | Given the same genome, metrics, and mutation strategy, two evolution runs produce identical results |
| R10 — Simpler Over Complex | Evolution strategies are declarative (strategy name + parameters) rather than imperative scripts |
| R13 — Design for Failure | Failed certification gates return structured diagnostics; mutation failures preserve original genome |
| R14 — Paved Path | Standard promotion path (Nascent → Master) is the default; custom paths require RFC |
| R15 — Open/Closed | Competency tree is extensible via new node types; evolution strategies are pluggable |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/AGS/000-Overview.md | AGS provides genome templates that AGX evolves |
| Bible/02-Core/Academy/000-Overview.md | Academy provides learning data for performance analysis |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy levels correspond to evolution stages |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou directs strategic evolution priorities |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA certifies capability upgrades for evolved agents |
| Bible/03-Institutions/Workers/000-Overview.md | Workers are the agents that evolve |
| Bible/05-Platform/004-EVS.md | EVS stores performance and failure evidence |
| Bible/00-Foundations/008-Object-Lifecycle.md | Lifecycle lifecycle governs agent stage transitions |
| Physics/007-Capabilities.md | Capability Bound invariants |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants |
