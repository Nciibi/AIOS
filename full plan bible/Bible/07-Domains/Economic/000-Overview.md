# AIOS Bible — Domains
## Economic — 000: System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-ECN-000 |
| Source Laws | Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Economic domain provides the resource economics infrastructure for AIOS — budgeting, cost accounting, resource pricing, and economic modeling. Every Worker consumes resources (compute, memory, storage, network, API calls), and every Organization has budgets that constrain that consumption. The Economic System tracks who spends what, ensures budgets are respected, prices resources consistently, and provides the data needed for economic decision-making.

The Economic System is not a financial ledger (that is EVS with evidence records) and not resource allocation (that is ROS). It is the economic layer that sits between resource consumption and organizational governance — it answers: how much does this cost, who pays for it, is there budget remaining, and how should we price resources to optimize utilization?

## Domain Entities

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| BudgetWorker | A Worker specialized for budget management and tracking | AGS: Economic/BudgetWorker |
| CostWorker | A Worker for cost accounting and allocation | AGS: Economic/CostWorker |
| PricingWorker | A Worker for resource pricing and rate setting | AGS: Economic/PricingWorker |
| Budget | A financial allocation with spending limits, time bounds, and policies | Economic System |
| CostReport | A periodic accounting of resource consumption and charges | Economic System |
| PriceSheet | A set of resource prices and rate schedules | Economic System |

## Capabilities

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Budget Management | `create_budget`, `allocate_funds`, `track_spending`, `forecast_burn`, `adjust_budget` | Low token, low compute |
| Cost Accounting | `record_cost`, `allocate_cost`, `compute_chargeback`, `generate_report` | Low token, medium compute |
| Resource Pricing | `set_price`, `compute_rate`, `model_demand`, `optimize_pricing` | Low token, high compute |
| Economic Modeling | `run_forecast`, `scenario_analysis`, `compute_roi`, `optimize_allocation` | Low token, very high compute |
| Budget Enforcement | `check_budget`, `reserve_funds`, `commit_spend`, `handle_overage` | Low token, low compute (real-time) |
| Audit & Compliance | `audit_spending`, `verify_budget`, `report_variance`, `trace_allocation` | Low token, low compute |

## Budget Lifecycle

Budgets follow a defined lifecycle from creation through closure:

```
Draft → Approved → Active → Frozen → Closed
```

| Phase | Description | Actions Allowed |
|-------|-------------|-----------------|
| Draft | Budget being planned, no spending | Edit, review, submit for approval |
| Approved | Budget approved but not yet in effect | Schedule activation |
| Active | Budget in effect, spending tracked | Spend, reserve, reallocate |
| Frozen | Spending suspended pending review | No new spending; existing commitments honored |
| Closed | Budget period ended, final accounting | Reporting only |

## Core Concepts

### 1. Resource Pricing

Every consumable resource in AIOS has a price: compute (per CPU-second), memory (per GB-hour), storage (per GB-month), network (per GB transfer), and API calls (per call). Prices are set by PricingWorkers based on supply, demand, and organizational policy. PriceSheets define the current rates and can vary by organization, priority tier, or time of day.

### 2. Budgets

A Budget is a time-bound allocation of fungible credits to an Organization, Mission, or Worker. Budgets have a total amount, a spending period (e.g., monthly), category limits (e.g., max 60% on compute), and an owner. Spending consumes from the budget in real-time; when the budget is exhausted, new spending is denied unless overage policies permit it.

### 3. Cost Accounting

Every resource consumption event produces a cost record: what was consumed, by whom, at what price, and which budget it was charged to. Cost records are stored in EVS as evidence (Law 4). Periodically, cost records are aggregated into CostReports that show spending by organization, project, worker type, and resource category.

### 4. Chargeback

Costs are allocated back to the consuming entity. Direct costs (e.g., "Worker A used 100 CPU-seconds") charge the Worker's parent Organization directly. Shared costs (e.g., "Database service used by 10 teams") are allocated proportionally based on usage. Chargeback enables accurate cost visibility for decision-making.

### 5. Budget Enforcement

When a Worker requests resources, the Budget System checks: does the responsible Organization have sufficient budget remaining? If yes, funds are reserved against the budget. If no, the request is denied (unless overage is allowed and configured). Budget enforcement is real-time and constitutional — spending without budget is a violation of Law 7 (Capability Bounds).

### 6. Economic Modeling

The Economic System supports what-if analysis: "What if we double the compute budget for Project X?" or "What if we reduce storage prices by 20%?" These models use historical cost data, current pricing, and demand projections to forecast outcomes. Modeling is advisory — it informs decisions but does not enforce them.

### 7. Overage and Reallocation

When a budget is approaching exhaustion, the Economic System can trigger: overage warnings (alert budget owner), automatic reallocation (move unused funds from another budget), escalation (notify Sou for strategic reprioritization), or hard denial (block new spending). Policies define which behavior applies per budget category.

## Data Model

```typescript
interface Budget {
  budgetId: string;
  name: string;
  ownerId: string;  // Organization, Mission, or Worker ID
  totalAmount: number;  // in credits
  spentAmount: number;
  reservedAmount: number;
  currency: 'credits';
  period: { start: Timestamp; end: Timestamp };
  status: 'draft' | 'approved' | 'active' | 'frozen' | 'closed';
  categoryLimits: CategoryLimit[];
  overagePolicy: OveragePolicy;
  createdAt: Timestamp;
  evidenceRef: string;
}

interface CostRecord {
  costId: string;
  resourceType: ResourceType;
  amount: number;
  unitPrice: number;
  totalCost: number;
  consumerId: string;  // Worker or Organization ID
  budgetId: string;
  chargeTargetId: string;  // Organization charged
  timestamp: Timestamp;
  evidenceRef: string;
}

interface PriceSheet {
  priceSheetId: string;
  name: string;
  effectiveFrom: Timestamp;
  effectiveTo: Timestamp | null;
  prices: ResourcePrice[];
  tier: 'standard' | 'premium' | 'critical';
  scope: 'global' | 'organization' | 'mission';
}

interface ResourcePrice {
  resourceType: ResourceType;
  unit: string;
  pricePerUnit: number;
  currency: 'credits';
  demandMultiplier?: number;  // dynamic pricing based on demand
}

interface CategoryLimit {
  resourceType: ResourceType;
  maxPercentage: number;  // percentage of total budget
}

interface CostReport {
  reportId: string;
  period: { start: Timestamp; end: Timestamp };
  totalSpend: number;
  byOrganization: Record<string, number>;
  byResourceType: Record<string, number>;
  byWorkerType: Record<string, number>;
  budgetVariance: BudgetVariance[];
  generatedAt: Timestamp;
}
```

## Interfaces

### Economic System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `createBudget(budget)` | Sou, Organization | Create a new budget |
| `getBudget(budgetId)` | Any | Retrieve budget details and current spending |
| `reserveFunds(budgetId, amount, consumerId)` | ROS, Worker | Reserve funds against a budget for upcoming spend |
| `commitSpend(budgetId, amount, consumerId, resourceType)` | ROS, Worker | Record actual spending against a budget |
| `checkBudget(budgetId, amount)` | ROS, Worker | Check if budget has sufficient remaining funds |
| `getPriceSheet(resourceType, tier)` | Any | Get current price for a resource type |
| `generateCostReport(period, scope)` | Organization, Academy | Generate a cost report for a time period |
| `forecastBurnRate(budgetId, horizon)` | Sou, Organization | Project when budget will be exhausted |
| `reallocateFunds(fromBudgetId, toBudgetId, amount)` | Sou | Move unused budget between allocations |
| `auditSpending(budgetId)` | Security Council | Full audit trail of all spending against a budget |

### Internal Interfaces

```typescript
interface BudgetManager {
  create(params: BudgetParams): Promise<Budget>;
  reserve(budgetId: string, amount: number, consumerId: string): Promise<ReservationResult>;
  commit(budgetId: string, amount: number, consumerId: string): Promise<CommitResult>;
  check(budgetId: string, amount: number): Promise<boolean>;
  freeze(budgetId: string, reason: string): Promise<void>;
  close(budgetId: string): Promise<CostReport>;
}

interface CostAllocator {
  record(consumption: ResourceConsumption): Promise<CostRecord>;
  allocateShared(cost: SharedCost, allocationBasis: AllocationBasis): Promise<CostRecord[]>;
  generateReport(period: TimeRange, scope: string): Promise<CostReport>;
}

interface PricingEngine {
  getPrice(resourceType: ResourceType, tier: string, orgId?: string): Promise<number>;
  computeRate(usage: ResourceUsage, priceSheet: PriceSheet): Promise<number>;
  optimizePrices(current: PriceSheet, demand: DemandForecast): Promise<PriceSheet>;
}

interface EconomicModeler {
  forecast(budgetId: string, horizon: Duration): Promise<BurnForecast>;
  scenario(baseBudget: Budget, changes: ScenarioChange[]): Promise<ScenarioResult>;
  computeROI(projectId: string, costData: CostReport, outcomeData: OutcomeData): Promise<ROIEstimate>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Budget Manager | Budget lifecycle — creation, tracking, freeze, close |
| Cost Allocator | Records consumption costs, allocates shared costs, generates reports |
| Pricing Engine | Maintains PriceSheets, computes rates, optimizes pricing |
| Enforcement Gateway | Real-time budget check before resource allocation |
| Economic Modeler | Forecasting, scenario analysis, ROI computation |
| Audit Ledger | Immutable cost record trail stored in EVS |

## Data Flow

```
Worker requests resource via ROS
        │
        ▼
Enforcement Gateway checks budget via checkBudget()
        │
        ├── Sufficient budget ──► reserveFunds() ──► Resource allocated
        │                                │
        │                                ▼
        │                         Worker uses resource
        │                                │
        │                                ▼
        │                         commitSpend() ──► CostRecord → EVS
        │
        └── Insufficient budget ──► OveragePolicy evaluation
                                        │
                                 ├── Allow overage ──► reserve with warning
                                 │
                                 └── Deny ──► Resource request rejected
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `ECN.BudgetCreated` | budgetId, ownerId, totalAmount | New budget registered |
| `ECN.BudgetActivated` | budgetId, effectiveFrom | Budget entered Active phase |
| `ECN.FundsReserved` | budgetId, amount, consumerId | Funds reserved for upcoming spend |
| `ECN.SpendCommitted` | budgetId, amount, consumerId, resourceType | Actual spending recorded |
| `ECN.BudgetThresholdWarning` | budgetId, spentPercentage, threshold | Spending approached configurable threshold |
| `ECN.BudgetExhausted` | budgetId, totalSpent, totalBudget | Budget fully consumed |
| `ECN.BudgetFrozen` | budgetId, reason | Budget suspended pending review |
| `ECN.BudgetClosed` | budgetId, finalReport | Budget period ended, final report generated |
| `ECN.PriceSheetUpdated` | priceSheetId, effectiveFrom, changes | Resource prices changed |
| `ECN.overageAllowed` | budgetId, amount | Overage policy triggered |
| `ECN.overageDenied` | budgetId, amount, consumerId | Spend denied due to insufficient budget |
| `ECN.CostReportGenerated` | reportId, period, totalSpend | Periodic cost report ready |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Budget not found | `ECN_BUDGET_NOT_FOUND` | Return error; no side effects |
| Budget in non-active state | `ECN_BUDGET_NOT_ACTIVE` | Reject spend; current state disallows spending |
| Insufficient budget remaining | `ECN_BUDGET_EXHAUSTED` | Deny spend; evaluate overage policy |
| Reserve amount exceeds budget total | `ECN_RESERVE_EXCEEDS_BUDGET` | Reject reserve; reduce amount or adjust budget |
| Resource type has no price defined | `ECN_UNPRICED_RESOURCE` | Reject; resource type must be priced first |
| Price sheet overlap detected | `ECN_PRICE_SHEET_CONFLICT` | Reject; overlapping effective dates for same scope |
| Budget category limit exceeded | `ECN_CATEGORY_LIMIT_EXCEEDED` | Deny spend against that resource type category |
| Cost record evidence missing | `ECN_EVIDENCE_MISSING` | Flag audit issue; record requires evidence ref |
| Budget period already closed | `ECN_BUDGET_PERIOD_CLOSED` | Reject; budget in terminal state, cannot be modified |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ECN-001 | Spending never exceeds the active budget total | Algorithmic — Enforcement Gateway blocks overspend |
| ECN-002 | Every cost record references a valid evidence record (Law 4) | Architectural — CostRecord requires evidenceRef |
| ECN-003 | A budget can only transition forward (Draft→Approved→Active→Frozen→Closed) | Algorithmic — state machine rejects backward transitions |
| ECN-004 | Reserved funds are deducted from available budget immediately | Architectural — reservation reduces available balance atomically |
| ECN-005 | Unused reserved funds are released when the reservation expires | Algorithmic — reservation TTL triggers automatic release |
| ECN-006 | Price sheets in the same scope cannot have overlapping effective periods | Algorithmic — validation on PriceSheet creation |
| ECN-007 | Total spending across all Organizations never exceeds platform-wide resource capacity | Constitutional — enforced by ROS at allocation time |
| ECN-008 | Overage decisions are always recorded as evidence | Architectural — overageAlways/Denied events emitted |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Economic System owns resource economics exclusively; ROS owns resource allocation; EVS owns evidence storage |
| R2 — Dependency Order | Depends on ROS (consumption data), EVS (evidence), ACF (dispatch); no circular dependencies |
| R3 — DRY | Resource prices defined once in PriceSheets; all cost computations reference, not duplicate |
| R4 — Builder Pattern | Budget creation uses builder for complex category limits and overage policy configuration |
| R9 — Deterministic | Given the same consumption and prices, cost computation produces identical results |
| R10 — Simpler Over Complex | Flat-rate pricing is default; demand-based dynamic pricing is opt-in |
| R13 — Design for Failure | Budget exhaustion blocks new spend but preserves existing reservations; cost records are immutable after creation |
| R14 — Paved Path | Organization-scoped monthly budget with category limits covers 80% of use cases |
| R15 — Open/Closed | New resource types can be priced by registering in PriceSheets; new allocation strategies are pluggable |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/05-Platform/002-ROS.md | ROS allocates resources; Economic System prices and budgets that allocation |
| Bible/05-Platform/004-EVS.md | EVS stores cost records as evidence |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime enforces resource consumption limits that tie to budgets |
| Bible/04-Execution/Workflow/000-Overview.md | WFE can include budget checks as workflow approval gates |
| Bible/02-Core/ROS/007-RMP.md | Resource Management Policy interacts with budget enforcement |
| Bible/03-Institutions/Organizations/000-Overview.md | Organizations are the primary budget owners |
| Bible/04-Execution/Simulation/000-Overview.md | Economic simulation domain models budget scenarios |
| Bible/02-Core/Academy/000-Overview.md | Academy learns from cost patterns to optimize resource usage |
| Bible/00-Foundations/008-Object-Lifecycle.md | Budget lifecycle governance |
| Physics/010-Execution.md | Execution consumes resources |
| Physics/007-Capabilities.md | Capability Bounds include resource consumption limits |
