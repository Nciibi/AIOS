# AIOS Bible — Domains
## Trading — 002: Risk Analysis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-TRD-002 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
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

| Event Type | Produced When | Fields |
|-------|----------|---------|
| Trading.RiskMetricsCalculated | RiskEngine: portfolioId, metrics, method | Published after risk metric computation |
| Trading.VaRComputed | VaRCalculator: portfolioId, varResult | Fired when VaR is recalculated |
| Trading.StressTestRun | StressTestRunner: portfolioId, scenarios, summary | Emitted after stress test completion |
| Trading.ExposureUpdated | ExposureTracker: portfolioId, report | Published on exposure change |
| Trading.LimitBreached | LimitEnforcer: limitId, scope, currentValue, maxValue | Fired when any limit threshold is crossed |
| Trading.LimitRestored | LimitEnforcer: limitId, scope, currentValue | Fired when a breached limit recovers |
| Trading.CorrelationUpdated | RiskEngine: matrixId, pairs | Emitted when correlation matrix is refreshed |

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

## Design DNA (R1-R6,R9,R10,R13-R15)

- **R1 — Single Source of Truth**: Position limits and exposure data are sourced from the canonical Portfolio state.
- **R2 — Immutable Event Log**: Every limit breach and risk computation is recorded as an immutable event.
- **R3 — Capability-Based Authorization**: Hard limit override requires RiskAdmin capability; all overrides are logged.
- **R4 — Law of Diminishing Returns**: Computational budget for stress testing is proportional to portfolio complexity.
- **R5 — Deterministic Computation**: VaR and correlation computations are reproducible from identical input snapshots.
- **R6 — Bounded Context**: Risk Analysis owns limits and risk models; portfolio construction belongs to Portfolio Management.
- **R9 — Fail-Fast**: Pre-trade risk checks reject orders immediately; never queue for deferred validation.
- **R10 — Audit Trail**: Every risk decision, limit change, and override is recorded with full identity context.
- **R13 — Defensive Design**: Correlated model failures cause fallback to conservative parametric VaR.
- **R14 — Self-Healing**: On transient correlation matrix failure, the previous valid matrix is reused with a staleness flag.
- **R15 — Backward Compatibility**: Risk metric schemas and scenario definitions maintain versioned migration paths.

## Related Documents

- Bible/07-Domains/Trading/001-Algorithms.md
- Bible/07-Domains/Trading/003-Market-Data.md
- Physics/005-Events.md
- Physics/007-Capabilities.md
- Physics/012-Experience.md
