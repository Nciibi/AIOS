# AIOS Bible â€” Domains
## Trading â€” 002: Risk Analysis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-TRD-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Risk Analysis domain provides real-time and pre-trade risk computation, VaR modeling, stress testing, exposure monitoring, position sizing, and correlation analysis. It enforces hard risk limits at the ROS (Rule of System) level and maintains a complete audit trail for every risk decision and limit check.

## Architecture

```
Position Data
    |
    v
Risk Factor Mapping
    |
    v
VaR Calculation ---> Limit Check
    |                     |
    v                     v
Stress Test         Exposure Report
    |
    v
Scenario Simulation
```

## Data Model (TypeScript)

```typescript
interface RiskMetrics {
  algorithmId: string;
  portfolioId: string;
  timestamp: Timestamp;
  var95: number;
  var99: number;
  cvar95: number;
  sharpe: number;
  sortino: number;
  maxDrawdown: number;
  volatility: number;
  beta: number;
}

interface VaRResult {
  id: string;
  portfolioId: string;
  method: "parametric" | "historical" | "monteCarlo";
  confidence: number;
  horizon: string;
  value: number;
  breakdown: Record<string, number>;
  computedAt: Timestamp;
}

interface StressScenario {
  id: string;
  name: string;
  shocks: Record<string, number>;
  probability: number;
  impact: number;
  breached: boolean;
}

interface ExposureReport {
  portfolioId: string;
  grossExposure: number;
  netExposure: number;
  longExposure: number;
  shortExposure: number;
  concentration: ConcentrationBreakdown;
  currencyExposure: Record<string, number>;
  generatedAt: Timestamp;
}

interface ConcentrationBreakdown {
  topFivePct: number;
  sectorPct: Record<string, number>;
  instrumentPct: Record<string, number>;
  maxSinglePct: number;
}

interface PositionLimit {
  id: string;
  scope: "instrument" | "assetClass" | "portfolio" | "global";
  limitType: "position" | "leverage" | "drawdown" | "concentration" | "velocity" | "counterparty" | "jurisdiction";
  maxValue: number;
  currentValue: number;
  hardLimit: boolean;
  breached: boolean;
  breachedAt: Timestamp | null;
}

interface CorrelationMatrix {
  id: string;
  symbols: string[];
  matrix: number[][];
  window: number;
  computedAt: Timestamp;
}
```

## Core Concepts / Operations

| Operation | Description | Input | Output |
|-----------|-------------|-------|--------|
| compute_var | Calculate Value-at-Risk using specified method | portfolioId, method, confidence | VaRResult |
| run_stress_test | Apply scenario shocks and measure impact | portfolioId, scenarioIds | StressScenario[] |
| monitor_exposure | Snapshot current portfolio exposures | portfolioId | ExposureReport |
| calculate_position_size | Determine max position size per risk rules | algorithmId, symbol, riskBudget | number |
| analyze_correlation | Compute pairwise correlation matrix | symbols[], window | CorrelationMatrix |
| check_limits | Validate all active limits against current state | portfolioId | LimitCheckResult |

## Internal Interfaces

| Interface | Consumer | Description |
|-----------|----------|-------------|
| RiskEngine | RiskWorker | Orchestrates risk computation pipeline |
| LimitEnforcer | RiskWorker, ExecutionWorker | Enforces hard limits pre-trade and continuously |
| VaRCalculator | RiskWorker | Computes VaR across multiple methodologies |
| StressTestRunner | RiskWorker | Executes scenario simulations |
| ExposureTracker | RiskWorker | Maintains real-time exposure snapshots |

## Events

| TRD.EventType |      Produced When | Fields |
|-------|----------|---------|
| TRD.RiskMetricsCalculated |      RiskEngine: portfolioId, metrics, method | Published after risk metric computation |
| TRD.VaRComputed |      VaRCalculator: portfolioId, varResult | Fired when VaR is recalculated |
| TRD.StressTestRun |      StressTestRunner: portfolioId, scenarios, summary | Emitted after stress test completion |
| TRD.ExposureUpdated |      ExposureTracker: portfolioId, report | Published on exposure change |
| TRD.LimitBreached |      LimitEnforcer: limitId, scope, currentValue, maxValue | Fired when any limit threshold is crossed |
| TRD.LimitRestored |      LimitEnforcer: limitId, scope, currentValue | Fired when a breached limit recovers |
| TRD.CorrelationUpdated |      RiskEngine: matrixId, pairs | Emitted when correlation matrix is refreshed |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| TRD-RSK-001 | Insufficient price history for VaR computation | MEDIUM | Fall back to parametric method, log warning |
| TRD-RSK-002 | Correlation matrix non-positive definite | HIGH | Regularize matrix, flag for review |
| TRD-RSK-003 | Stress scenario computation diverges (NaN/Inf results) | HIGH | Discard scenario, alert analyst |
| TRD-RSK-004 | Limit enforcement system unavailable during pre-trade check | CRITICAL | Block order execution, fall back to conservative limits |
| TRD-RSK-005 | Exposure snapshot stale by more than 5 seconds | MEDIUM | Recompute immediately, alert on latency |
| TRD-RSK-006 | Model instability detected (VaR oscillation > threshold) | MEDIUM | Increase lookback window, log event |
| TRD-RSK-007 | Concentration limit breached without previous warning | HIGH | Auto-rebalance or halt new positions per policy |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| TRD-RSK-INV-001 | Hard risk limits (position, leverage, drawdown, concentration, velocity) are enforced at the ROS level and cannot be bypassed by any capability | Gate check in LimitEnforcer before order submission |
| TRD-RSK-INV-002 | Every risk check produces a complete audit record with timestamp, identity, and result | Immutable append to RiskAuditLog |
| TRD-RSK-INV-003 | Pre-trade risk checks must pass before any order reaches ExecutionWorker | Synchronous blocking call in order pipeline |
| TRD-RSK-INV-004 | VaR computation must use at least 250 trading days of history | Precondition validation in VaRCalculator |
| TRD-RSK-INV-005 | Correlation matrix must be recomputed at least once per trading day | Scheduled job in RiskEngine |
| TRD-RSK-INV-006 | Stress scenarios must cover at least 5 distinct shock types (equity, FX, rates, credit, commodity) | Validation check on scenario registration |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Compliant |
| R2 - Dependency Order | Compliant |
| R3 - DRY | Compliant |
| R4 - Builder Pattern | Compliant |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Compliant |
| R10 - Simpler Over Complex | Compliant |
| R13 - Design for Failure | Compliant |
| R14 - Paved Path | Compliant |
| R15 - Open/Closed | Compliant |

## Cross-Cutting Concerns

### Security

Trading operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Trading emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Trading instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Trading declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Trading/000-Overview.md | Base Trading domain overview |
| Bible/07-Domains/Trading/001-Algorithms.md | Algorithms produce the positions that risk analysis monitors |
| Bible/07-Domains/Trading/003-Market-Data.md | Market data feeds risk model computation |
| Physics/005-Events.md | Evidence â€” risk operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” risk capability bounds |
| Physics/012-Experience.md | Experience â€” risk outcomes drive strategy improvement |
