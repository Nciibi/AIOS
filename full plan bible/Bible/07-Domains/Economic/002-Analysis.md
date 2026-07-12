# AIOS Bible â€” Domains
## Economic â€” 002: Cost Analysis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-ECN-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle Compliance, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Cost Analysis sub-domain provides the cost allocation and analysis infrastructure for AIOS â€” cost allocation rule management, chargeback computation, variance analysis, trend detection, optimization recommendations, and cost attribution. Analysis consumes CostRecords and CostReports (defined in Economic/000-Overview.md) and produces actionable insights that inform budget planning, resource optimization, and organizational chargeback. Every allocation and analysis must be traceable to evidence records (Law 4). The analysis engine supports periodic reconciliation cycles and variance alerts (Law 6).

## Architecture

```
Cost Data Ingestion (CostRecords, CostReports from EVS)
        â”‚
        â–¼
Allocation Rule Application â”€â”€â–º Chargeback Computation â”€â”€â–º Variance Detection
        â”‚                                                    â”‚
        â–¼                                                    â–¼
Cost Attribution                                          Trend Analysis
        â”‚                                                    â”‚
        â–¼                                                    â–¼
Optimization Recommendations â—„â”€â”€â”€â”€â”€â”€ Report Generation
```

The pipeline ingests cost records from EVS, applies configured allocation rules to categorize costs, computes chargeback amounts per consuming entity, detects variance against budget baselines, analyzes trends over time windows, attributes costs to sources, and generates optimization recommendations. Each stage can emit events and failures independently.

## Data Model (TypeScript â€” extend the base doc types from Economic/000-Overview.md)

```typescript
interface CostAllocationRule {
  ruleId: string;
  name: string;
  resourceType: ResourceType;
  strategy: 'direct' | 'proportional' | 'fixed' | 'weighted';
  allocationBasis: AllocationBasis;
  targets: string[];  // Organization IDs eligible for allocation
  effectiveFrom: Timestamp;
  effectiveTo: Timestamp | null;
  priority: number;  // lower number = higher priority
  conflictResolution: 'first_match' | 'most_specific' | 'highest_priority';
}

interface ChargebackRecord {
  chargebackId: string;
  period: { start: Timestamp; end: Timestamp };
  consumerId: string;  // Organization or Worker charged
  resourceType: ResourceType;
  directCost: number;
  allocatedCost: number;
  totalCharged: number;
  ruleId: string;
  sourceRecords: string[];  // CostRecord IDs
  computedAt: Timestamp;
  evidenceRef: string;
}

interface VarianceReport {
  reportId: string;
  budgetId: string;
  period: { start: Timestamp; end: Timestamp };
  budgetedAmount: number;
  actualSpend: number;
  variance: number;
  variancePercentage: number;
  severity: 'favorable' | 'minor' | 'significant' | 'critical';
  rootCauses: VarianceCause[];
  generatedAt: Timestamp;
}

interface CostTrend {
  trendId: string;
  resourceType: ResourceType;
  consumerId: string;
  timeWindow: { start: Timestamp; end: Timestamp };
  direction: 'increasing' | 'decreasing' | 'stable' | 'volatile';
  slope: number;
  seasonalityDetected: boolean;
  seasonalPeriod: Duration | null;
  anomalyPoints: AnomalyPoint[];
  projectedNextPeriod: number;
}

interface AttributionResult {
  attributionId: string;
  totalCost: number;
  byOrganization: AttributionBreakdown[];
  byWorker: AttributionBreakdown[];
  byResource: AttributionBreakdown[];
  byMission: AttributionBreakdown[];
  uncategorizedCost: number;
  confidence: number;  // 0.0 to 1.0
}

interface OptimizationRecommendation {
  recommendationId: string;
  type: 'resize' | 'reallocate' | 'deprecate' | 'reserve' | 'discount';
  resourceType: ResourceType;
  currentCost: number;
  projectedSavings: number;
  implementationCost: number;
  paybackPeriod: Duration;
  riskLevel: 'low' | 'medium' | 'high';
  rationale: string;
  supportingData: string;  // reference to analysis evidence
}

interface AllocationBasis {
  metric: 'usage_volume' | 'worker_count' | 'request_count' | 'revenue' | 'headcount';
  weightExpression?: string;  // e.g. "2 * cpu_hours + memory_gb"
}

interface VarianceCause {
  factor: string;
  contribution: number;  // percentage of total variance explained
  detail: string;
  evidenceRef: string;
}

interface AnomalyPoint {
  timestamp: Timestamp;
  actualValue: number;
  expectedValue: number;
  deviation: number;
  probableCause: string;
}
```

## Core Concepts / Operations

### 1. Cost Allocation Rules

Rules determine how costs are assigned to consuming entities. Direct allocation charges the exact consumer. Proportional allocation divides shared costs based on usage metrics. Fixed allocation assigns predetermined amounts. Weighted allocation uses custom weight expressions. Rule conflicts are resolved by priority and strategy.

### 2. Chargeback Computation

Chargeback produces per-entity cost summaries for a period. Direct costs are charged to the consuming Worker's parent Organization. Shared costs are allocated across all beneficiaries proportionally. Every chargeback record references its source cost records for full traceability.

### 3. Variance Detection

Variance analysis compares actual spend against budget baselines. Variance is classified by severity and root causes are identified. Significant variances trigger alerts and investigation workflows. Favorable variances (under-budget) are also recorded for budget optimization.

### 4. Trend Analysis

Cost trends are computed over configurable time windows. Direction, slope, and seasonality are detected automatically. Anomaly points (unexpected spikes or drops) are flagged for investigation. Trends feed into the optimization recommendation engine.

### 5. Cost Attribution

Attribution traces costs back to their sources across multiple dimensions: organization, worker, resource type, and mission. Uncategorized costs are identified for rule refinement. Attribution confidence improves with more granular allocation rules.

### 6. Optimization Recommendations

Based on cost trends, variance, and attribution data, the engine recommends optimizations: resizing resources, reallocating budgets, deprecating unused resources, purchasing reservations, or applying discount plans. Each recommendation includes projected savings, implementation cost, and risk level.

### 7. Reconciliation Cycle

Periodic reconciliation ensures every cost record is allocated and accounted. Unallocated costs are flagged as exceptions. Reconciliation runs at configurable intervals (daily, weekly, monthly) and produces reconciliation reports.

## Internal Interfaces

```typescript
interface AllocationEngine {
  createRule(params: AllocationRuleParams): Promise<CostAllocationRule>;
  applyRules(costRecords: CostRecord[]): Promise<AllocationResult[]>;
  resolveConflict(ruleA: CostAllocationRule, ruleB: CostAllocationRule): Promise<CostAllocationRule>;
  validateRules(rules: CostAllocationRule[]): Promise<ValidationResult>;
}

interface ChargebackComputer {
  computeChargeback(costRecords: CostRecord[], period: TimeRange): Promise<ChargebackRecord[]>;
  computeDirect(record: CostRecord): Promise<ChargebackRecord>;
  computeShared(cost: SharedCost, basis: AllocationBasis): Promise<ChargebackRecord[]>;
}

interface VarianceAnalyzer {
  detectVariance(actuals: CostReport, budgets: Budget[]): Promise<VarianceReport[]>;
  classifyVariance(variance: number, threshold: VarianceThreshold): VarianceSeverity;
  attributeRootCause(variance: VarianceReport, costRecords: CostRecord[]): Promise<VarianceCause[]>;
}

interface TrendDetector {
  analyzeTrend(costRecords: CostRecord[], window: Duration): Promise<CostTrend>;
  detectAnomalies(trend: CostTrend, sensitivity: number): Promise<AnomalyPoint[]>;
  projectNext(trend: CostTrend): Promise<number>;
}

interface OptimizationEngine {
  findOptimizations(costReport: CostReport, trends: CostTrend[]): Promise<OptimizationRecommendation[]>;
  estimateSavings(recommendation: OptimizationRecommendation): Promise<number>;
  rankByROI(recommendations: OptimizationRecommendation[]): Promise<OptimizationRecommendation[]>;
}
```

## Events

| ECON.EventType |    Produced When | Fields |
|-------|--------|-------------|
| ECON.AllocationRuleCreated |    ruleId, name, strategy, targets | New cost allocation rule registered |
| ECON.AllocationRuleApplied |    ruleId, recordsAffected, totalAllocated | Allocation rule executed against cost records |
| ECON.CostsAllocated |    period, totalDirect, totalShared, entitiesCount | Batch allocation completed for a period |
| ECON.ChargebackComputed |    chargebackId, consumerId, totalCharged | Chargeback record generated for an entity |
| ECON.VarianceDetected |    reportId, budgetId, variancePercentage, severity | Budget variance threshold crossed |
| ECON.VarianceEscalated |    reportId, severity, rootCauseCount | Variance requires management attention |
| ECON.TrendReported |    trendId, resourceType, direction, slope | Cost trend analysis completed |
| ECON.AnomalyDetected |    trendId, timestamp, deviation, probableCause | Unexpected cost spike or drop flagged |
| ECON.OptimizationGenerated |    recommendationId, projectedSavings, paybackPeriod | Cost optimization recommendation created |
| ECON.ReconciliationComplete |    period, totalAllocated, totalUnallocated, unallocatedCount | Periodic cost reconciliation finished |

## Error Cases

| Error Code | Condition | Severity | Recovery |
|------------|-----------|----------|---------|
| `ECN_ALLOCATION_RULE_CONFLICT` | Two or more rules with same priority and overlapping scope | Error | Flag for manual resolution; skip conflicting rules until resolved |
| `ECN_MISSING_COST_DATA` | Required cost records for a period are missing or incomplete | Warning | Generate partial report; flag missing data for investigation |
| `ECN_UNALLOCABLE_COST` | Cost record has no matching allocation rule for its resource type | Warning | Attribute to unallocated pool; recommend rule creation |
| `ECN_VARIANCE_THRESHOLD_EXCEEDED` | Variance exceeds maximum configured threshold | Error | Escalate to budget owner; freeze budget if configured |
| `ECN_CHARGEBACK_OVERLAP` | Same cost allocated to multiple entities exceeding total | Error | Recompute with conflict resolution; flag duplicate records |
| `ECN_INCONSISTENT_ATTRIBUTION` | Attribution breakdown sums do not equal total cost | Error | Recalculate attributions; integrity check failed |
| `ECN_TREND_INSUFFICIENT_HISTORY` | Not enough historical data points for trend analysis | Warning | Reduce time window or defer trend analysis |
| `ECN_OPTIMIZATION_INFEASIBLE` | Projected savings do not justify implementation cost | Warning | Downgrade recommendation priority; flag for review |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ECN-ANA-001 | Every cost record is allocated to exactly one entity | Algorithmic â€” allocation engine ensures complete coverage |
| ECN-ANA-002 | Sum of all chargeback amounts equals total spend for the period | Algorithmic â€” reconciliation validates chargeback sums |
| ECN-ANA-003 | Allocation rules cannot have overlapping effective dates for same resource type | Algorithmic â€” validation rejects rule date conflicts |
| ECN-ANA-004 | Every chargeback record references its source cost records | Architectural â€” sourceRecords array is required |
| ECN-ANA-005 | Variance reports are regenerated on every budget state change | Algorithmic â€” budget transitions trigger variance recomputation |
| ECN-ANA-006 | Optimization recommendations include risk assessment | Architectural â€” OptimizationRecommendation.riskLevel is required |


## Cross-Cutting Concerns

### Security

Economic operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Economic emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Economic instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Economic declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Cost Analysis owns allocation, chargeback, variance, and trends; Budget Management owns budget state; Models owns forecasting |
| R2 - Dependency Order | Depends on Economic (CostRecords, CostReports, Budget), EVS (evidence), ACF (dispatch); no circular dependencies |
| R3 - DRY | Allocation rules defined once and reused across periods; cost records are singular sources of truth |
| R4 - Builder Pattern | CostAllocationRule uses builder for complex allocation basis and weight expressions |
| R5 - Liskov Substitution | Allocation computation is stateless given the same inputs; rule state is in the rule definition |
| R6 - DI over Singletons | Every allocation, chargeback, and variance analysis produces an evidence record |
| R9 - Deterministic | Same cost records and allocation rules produce identical chargeback results |
| R10 - Simpler Over Complex | Direct allocation is default; proportional and weighted allocation are opt-in |
| R13 - Design for Failure | Unallocated costs are flagged not lost; variance escalation ensures visibility |
| R14 - Paved Path | Monthly chargeback by organization with direct allocation covers 80% of use cases |
| R15 - Open/Closed | New allocation strategies are pluggable; new resource types use existing rules |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Economic/000-Overview.md | Base Economic System â€” defines Budget, CostRecord, CostReport base types |
| Bible/07-Domains/Economic/001-Models.md | Economic Models provides trend forecasts that feed optimization |
| Bible/07-Domains/Economic/003-Simulation.md | Simulation uses cost analysis data for scenario modeling |
| Bible/02-Core/ROS/000-Overview.md | ROS provides resource consumption records that fuel cost analysis |
| Bible/05-Platform/004-EVS.md | EVS stores all cost allocation evidence records |
| Bible/03-Institutions/Organizations/000-Overview.md | Organizations are the primary targets for chargeback |
| Bible/00-Foundations/008-Object-Lifecycle.md | Budget lifecycle governs when variance analysis occurs |
| Physics/010-Execution.md | Execution resource consumption is the raw material for cost analysis |
| Physics/007-Capabilities.md | Capability bounds constrain allocation rule complexity and scope |
