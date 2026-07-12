# AIOS Bible — Domains
## Trading — 001: Algorithms

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-TRD-001 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Trading Algorithms domain provides the engine for defining, parameterizing, executing, and optimizing automated trading strategies. It bridges quantitative research and live order execution by enforcing deterministic signal generation, strict parameter bounds, and reproducible backtest semantics across the strategy lifecycle.

## Architecture

```
Strategy Definition
    |
    v
Parameter Configuration
    |
    v
Signal Generation
    |
    v
Order Construction
    |
    v
Execution Logic
```

## Data Model (TypeScript)

```typescript
interface TradingAlgorithm {
  id: string;
  name: string;
  version: string;
  template: AlgorithmTemplate;
  params: StrategyParams;
  status: "draft" | "backtesting" | "paper" | "live" | "paused" | "retired";
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

interface StrategyParams {
  symbols: string[];
  timeframe: "1m" | "5m" | "15m" | "1h" | "4h" | "1d";
  lookbackPeriod: number;
  thresholds: Record<string, number>;
  constraints: ParamBounds;
  metadata: Record<string, unknown>;
}

interface ParamBounds {
  min: Record<string, number>;
  max: Record<string, number>;
  step: Record<string, number>;
}

interface SignalGenerator {
  algorithmId: string;
  type: "momentum" | "meanReversion" | "arbitrage" | "ml" | "custom";
  indicators: IndicatorConfig[];
  aggregation: "AND" | "OR" | "weighted";
  cooldownMs: number;
}

interface IndicatorConfig {
  name: string;
  params: Record<string, number>;
  source: "open" | "high" | "low" | "close" | "volume" | "vwap";
}

interface OrderConstruction {
  algorithmId: string;
  orderType: "market" | "limit" | "stop" | "stopLimit" | "twap" | "vwap";
  side: "buy" | "sell";
  quantityModel: "fixed" | "percent" | "dynamic";
  quantityValue: number;
  maxSlippage: number;
  timeInForce: "day" | "gtc" | "ioc" | "fok";
}

interface ExecutionLogic {
  algorithmId: string;
  exchangePriority: string[];
  routing: "smart" | "direct" | "darkpool";
  retryConfig: { maxAttempts: number; backoffMs: number };
  fallback: "cancel" | "reduce" | "reroute";
}

interface AlgorithmTemplate {
  id: string;
  category: string;
  description: string;
  defaults: Partial<StrategyParams>;
  requiredIndicators: string[];
}
```

## Core Concepts / Operations

| Operation | Description | Input | Output |
|-----------|-------------|-------|--------|
| implement_strategy | Register a new algorithm from a template | templateId, params | TradingAlgorithm |
| configure_parameters | Set or validate strategy parameters | algorithmId, params | StrategyParams |
| generate_signal | Compute trading signal from market data | algorithmId, marketData | Signal |
| construct_order | Build order payload from signal | algorithmId, signal | OrderPayload |
| optimize_parameters | Run parameter optimization over historical data | algorithmId, dateRange, metric | OptimizationResult |

## Internal Interfaces

| Interface | Consumer | Description |
|-----------|----------|-------------|
| StrategyEngine | TradingWorker | Orchestrates strategy lifecycle |
| SignalBus | QuantWorker | Distributes generated signals |
| OrderFactory | ExecutionWorker | Constructs validated orders |
| ParamRegistry | RiskWorker | Provides parameter bounds for risk checks |
| BacktestRunner | TradingWorker | Executes historical simulations |

## Events

| Event Type | Produced When | Fields |
|-------|----------|---------|
| Trading.AlgorithmImplemented | StrategyEngine: algorithmId, templateId, version | Fired when a new algorithm is registered |
| Trading.AlgorithmConfigured | StrategyEngine: algorithmId, params, hash | Fired after parameter update |
| Trading.SignalGenerated | SignalBus: algorithmId, signal, confidence, timestamp | Emitted on each signal computation |
| Trading.OrderConstructed | OrderFactory: algorithmId, orderPayload, checksum | Fired when an order is built |
| Trading.AlgorithmOptimized | Optimizer: algorithmId, metrics, optimalParams | Fired after optimization run |
| Trading.AlgorithmDeployed | StrategyEngine: algorithmId, targetEnv | Fired on promotion to paper/live |
| Trading.AlgorithmPaused | StrategyEngine: algorithmId, reason | Fired when algorithm is halted |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| TRD-ALG-001 | Strategy logic throws unhandled exception during signal generation | HIGH | Isolate algorithm, alert developer, fall back to no-op |
| TRD-ALG-002 | Parameter value exceeds defined bounds | MEDIUM | Clamp to boundary, log warning, reject update |
| TRD-ALG-003 | Signal latency exceeds max threshold (configurable per algorithm) | MEDIUM | Drop stale signal, log alert, adjust cooldown |
| TRD-ALG-004 | Optimization produces overfit model (train/test divergence > 15%) | HIGH | Discard result, require manual override |
| TRD-ALG-005 | Required indicator data unavailable for signal computation | MEDIUM | Return neutral signal, log data gap |
| TRD-ALG-006 | Order construction produces invalid payload (missing fields) | HIGH | Reject order, log validation failure |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| TRD-ALG-INV-001 | Signal generation for identical market data and parameters must produce identical output | Unit test on SignalBus; hash comparison on every generation |
| TRD-ALG-INV-002 | All parameter updates must be validated against declared bounds before acceptance | Precondition check in configure_parameters; reject on violation |
| TRD-ALG-INV-003 | Backtest and live execution must use identical signal logic (no branching) | Single code path enforced via compilation guard |
| TRD-ALG-INV-004 | Every algorithm version must have a corresponding backtest result before live deployment | Gateway check in StrategyEngine deploy pipeline |
| TRD-ALG-INV-005 | Cooldown period between consecutive signals of same direction must be enforced | Sliding window check in SignalGenerator |

## Design DNA (R1-R6,R9,R10,R13-R15)

- **R1 — Single Source of Truth**: Strategy parameters live in ParamRegistry; signals and orders are derived.
- **R2 — Immutable Event Log**: Every signal generation and order construction produces an immutable event.
- **R3 — Capability-Based Authorization**: Only the StrategyEngine capability may deploy algorithms to live.
- **R4 — Law of Diminishing Returns**: Optimization penalizes parameter count vs. out-of-sample performance.
- **R5 — Deterministic Computation**: All signal generators are pure functions of market data and parameters.
- **R6 — Bounded Context**: Algorithm templates own their domain; cross-strategy coordination goes through TradingWorker.
- **R9 — Fail-Fast**: Invalid parameters or signals are rejected at the boundary, never silently corrected.
- **R10 — Audit Trail**: Every parameter change, signal, and order construction is logged with timestamp and identity.
- **R13 — Defensive Design**: Stale signals are dropped; missing indicators produce neutral output.
- **R14 — Self-Healing**: On transient indicator failure, signal computation retries once with exponential backoff.
- **R15 — Backward Compatibility**: Algorithm templates and parameter schemas maintain versioned migration paths.

## Related Documents

- Bible/07-Domains/Trading/002-Risk-Analysis.md
- Bible/07-Domains/Trading/003-Market-Data.md
- Physics/005-Events.md
- Physics/007-Capabilities.md
- Physics/012-Experience.md
