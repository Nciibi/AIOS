# AIOS Bible â€” Domains
## Trading â€” 001: Algorithms

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-TRD-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
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

| TRD.EventType |  Produced When | Fields |
|-------|----------|---------|
| TRD.AlgorithmImplemented |  StrategyEngine: algorithmId, templateId, version | Fired when a new algorithm is registered |
| TRD.AlgorithmConfigured |  StrategyEngine: algorithmId, params, hash | Fired after parameter update |
| TRD.SignalGenerated |  SignalBus: algorithmId, signal, confidence, timestamp | Emitted on each signal computation |
| TRD.OrderConstructed |  OrderFactory: algorithmId, orderPayload, checksum | Fired when an order is built |
| TRD.AlgorithmOptimized |  Optimizer: algorithmId, metrics, optimalParams | Fired after optimization run |
| TRD.AlgorithmDeployed |  StrategyEngine: algorithmId, targetEnv | Fired on promotion to paper/live |
| TRD.AlgorithmPaused |  StrategyEngine: algorithmId, reason | Fired when algorithm is halted |

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

- **R1 â€” Single Source of Truth**: Strategy parameters live in ParamRegistry; signals and orders are derived.
- **R2 â€” Immutable Event Log**: Every signal generation and order construction produces an immutable event.
- **R3 â€” Capability-Based Authorization**: Only the StrategyEngine capability may deploy algorithms to live.
- **R4 â€” Law of Diminishing Returns**: Optimization penalizes parameter count vs. out-of-sample performance.
- **R5 â€” Deterministic Computation**: All signal generators are pure functions of market data and parameters.
- **R6 â€” Bounded Context**: Algorithm templates own their domain; cross-strategy coordination goes through TradingWorker.
- **R9 â€” Fail-Fast**: Invalid parameters or signals are rejected at the boundary, never silently corrected.
- **R10 â€” Audit Trail**: Every parameter change, signal, and order construction is logged with timestamp and identity.
- **R13 â€” Defensive Design**: Stale signals are dropped; missing indicators produce neutral output.
- **R14 â€” Self-Healing**: On transient indicator failure, signal computation retries once with exponential backoff.
- **R15 â€” Backward Compatibility**: Algorithm templates and parameter schemas maintain versioned migration paths.



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
| Bible/07-Domains/Trading/002-Risk-Analysis.md | Risk analysis validates algorithm risk parameters |
| Bible/07-Domains/Trading/003-Market-Data.md | Market data feeds algorithm signal generation |
| Physics/005-Events.md | Evidence â€” algorithm operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” algorithm capability bounds |
| Physics/012-Experience.md | Experience â€” algorithm outcomes drive strategy improvement |
