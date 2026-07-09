# AIOS Bible — Domains
## Trading — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-TRD-000 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Trading domain enables AIOS to develop, backtest, deploy, and monitor automated financial trading strategies — across equities, futures, options, forex, and cryptocurrency markets. It provides the capability set for strategy research, quantitative model development, risk management, order execution, and portfolio management.

Trading is a domain where speed, accuracy, and risk management are paramount. Financial markets operate under strict regulatory regimes, and trading errors can have significant financial consequences. The Trading domain therefore emphasizes simulation-first validation, strict capability bounds on order sizes and instruments, comprehensive audit trails, and compliance with jurisdictional regulations.

## Domain Entities

The Trading domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| TradingWorker | A Worker specialized for trading strategy development | AGS: Trading/TradingWorker |
| QuantWorker | A Worker for quantitative model development | AGS: Trading/QuantWorker |
| RiskWorker | A Worker for risk analysis and monitoring | AGS: Trading/RiskWorker |
| ExecutionWorker | A Worker for order execution management | AGS: Trading/ExecutionWorker |
| TradingStrategy | A knowledge artifact for a validated trading strategy | Academy: Knowledge |
| MarketModel | A knowledge artifact for a market regime model | Academy: Knowledge |

## Capabilities

The Trading domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Strategy Research | `research_strategy`, `analyze_market`, `test_hypothesis`, `optimize_parameters` | High token, high compute |
| Quantitative Modeling | `build_model`, `train_ml`, `feature_engineering`, `validate_model` | Low token, high compute (GPU) |
| Backtesting | `run_backtest`, `simulate_execution`, `analyze_performance`, `compute_metrics` | Low token, very high compute |
| Risk Management | `compute_var`, `stress_test`, `monitor_exposure`, `set_limits` | Low token, medium compute |
| Order Execution | `place_order`, `manage_position`, `optimize_execution`, `handle_fill` | Low token, I/O bound (latency-sensitive) |
| Portfolio Management | `allocate_capital`, `rebalance_portfolio`, `optimize_weights`, `track_pnl` | Low token, medium compute |
| Compliance | `check_regulation`, `audit_trades`, `report_positions`, `verify_limits` | Medium token, low compute |

## Trading Strategy Lifecycle

Trading strategies follow a rigorous validation lifecycle:

```
Idea → Research → Backtest → Paper Trade → Deploy → Monitor → Retire
```

| Phase | Description | Verification Required |
|-------|-------------|----------------------|
| Idea | Strategy concept defined | Peer review (ResearchWorker) |
| Research | Hypothesis tested on historical data | Statistical significance verified |
| Backtest | Full historical simulation with realistic costs | DTS confidence ≥ 0.7 |
| Paper Trade | Live market simulation without real capital | DTS confidence ≥ 0.8 |
| Deploy | Live trading with real capital, bounded position | DTS confidence ≥ 0.9 + RiskWorker approval |
| Monitor | Ongoing performance tracking | Daily risk checks |
| Retire | Strategy decommissioned | Performance degradation or regime change |

No strategy may proceed to Deploy without passing through all prior phases. DTS confidence thresholds are enforced by the Trading domain.

## Risk Controls

The Trading domain enforces multi-layer risk controls:

| Layer | Control | Limit Source |
|-------|---------|-------------|
| Instrument | Only authorized instruments may be traded | Organization policy |
| Position | Maximum position size per instrument | Risk policy + ROS budget |
| Leverage | Maximum leverage ratio | Risk policy |
| Drawdown | Maximum acceptable drawdown (daily + total) | Risk policy |
| Concentration | Maximum exposure to single instrument/sector | Risk policy |
| Velocity | Maximum trade frequency | Risk policy + Market rules |
| Counterparty | Only approved counterparties | Organization policy |
| Jurisdiction | Only compliant jurisdictions | Compliance policy |

All risk limits are enforced by ROS budget allocation. A trade that would violate a limit is rejected before reaching the exchange.

## Invariants

1. **TRD-I-001 — Simulation Before Capital**: No strategy may trade with real capital without passing backtest AND paper trading phases. Backtest-only strategies are research artifacts, not deployable strategies.

2. **TRD-I-002 — Hard Risk Limits**: Risk limits are enforced at the ROS allocation level. A trade that would violate a position, drawdown, or concentration limit is rejected before reaching the exchange. Software overrides are prohibited.

3. **TRD-I-003 — Complete Audit Trail**: Every order, fill, rejection, and risk event is recorded in the Event Store. The complete trade lifecycle for every order must be reconstructable from Events.

4. **TRD-I-004 — Market Data Integrity**: All market data used for decision-making must be validated before use. Stale, missing, or obviously erroneous data must be handled through defined degraded modes.

5. **TRD-I-005 — Best Execution**: Orders must be routed to achieve best execution considering price, speed, and likelihood of execution. Order routing decisions are recorded and auditable.

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Exchange API is unreachable | Orders queued locally with TTL. If exchange remains unreachable, orders expire and risk positions are reconciled. |
| Market data feed is delayed | Timestamp comparison against expected latency threshold. If delay exceeds threshold, trading paused until feed validated. |
| Backtest shows overfitting indicators | DTS confidence reduced. Walk-forward analysis triggered. If overfitting confirmed, strategy returned to research. |
| Order partially filled | Remaining quantity re-priced and re-submitted. Fill record captures partial fill details. |
| Strategy P&L exceeds daily drawdown limit | Automatic position liquidation. Trading halted for the day. Security Council notified. |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Trading.StrategyResearched` | Strategy research completes | strategy_id, hypothesis, instruments, time_horizon, confidence, methodology |
| `Trading.BacktestRun` | Backtest execution finishes | backtest_id, strategy_id, start_date, end_date, sharpe, max_drawdown, total_return, trades_count |
| `Trading.PaperTradeCompleted` | Paper trading phase finishes | paper_id, strategy_id, trades_executed, pnl, fill_quality, slippage_analysis |
| `Trading.StrategyDeployed` | Strategy is deployed to live trading | strategy_id, capital_allocated, risk_limits, deployed_at, dts_confidence |
| `Trading.OrderPlaced` | Order is submitted to exchange | order_id, instrument, side, quantity, order_type, limit_price, exchange_route |
| `Trading.OrderFilled` | Order execution confirmed | order_id, fill_price, fill_quantity, fees, timestamp, liquidity_taker |
| `Trading.OrderRejected` | Order is rejected by exchange or risk | order_id, reason, rejection_source, suggested_action |
| `Trading.RiskLimitBreached` | A risk limit is approached or breached | limit_type, current_value, limit_value, action_taken, strategy_id |
| `Trading.StrategyRetired` | Strategy is decommissioned | strategy_id, reason, final_pnl, lessons_learned, total_trades |

## Cross-Cutting Concerns

### Security

Trading Workers operate in sandboxed environments with no direct exchange access — all orders pass through the ExecutionWorker which enforces risk limits. API keys and exchange credentials are managed by KMS and never exposed to strategy Workers. Order placement is authenticated and authorized per trade. (Physics/008-Security.md)

### Evidence

Every trading operation produces an Event — research, backtest, paper trade, order placement, fill, and risk check. The complete trade lifecycle is recorded in the Event Store for audit, compliance, and post-trade analysis. Strategy performance evidence feeds into Academy knowledge. (PHI-008)

### Lifecycle

Trading Workers follow the canonical Worker lifecycle. Strategies follow the trading strategy lifecycle. Backtests and paper trades are batch jobs. Live trading sessions follow an operational lifecycle (Market Open → Active → Market Close → Settlement). (Physics/006-Lifecycles.md)

### Capability Bounds

Trading capabilities are bounded by instrument authorization, position limits, and capital allocation. A TradingWorker may only trade instruments registered in its Genome. Position sizes are bounded by ROS budget. No strategy may deploy without passing DTS confidence thresholds. (Physics/007-Capabilities.md)

### Communication

All Trading domain communication flows through ACF. Market data arrives through ACF from exchange feed providers. Orders are submitted through ACF to execution gateways. Risk alerts are high-priority ACF messages delivered to the RiskWorker and Security Council. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each trading capability (research, model, backtest, risk, execute, portfolio) is separate |
| R5 (Liskov) | All exchange adapters implement the ExchangeInterface |
| R9 (Deterministic) | Same strategy and market data produces identical backtest results |
| R10 (Simpler Over Complex) | Strategy deployment follows linear lifecycle — no shortcuts |
| R13 (Design for Failure) | Order failures trigger automatic position reconciliation; exchange disconnects trigger circuit breaker |
| R14 (Paved Path) | Paved path: research → backtest → paper → deploy → monitor → retire |

## Performance Characteristics

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Strategy research | < 60 minutes | 4 hours |
| Backtest (1 year, 1 instrument) | < 5 minutes | 15 minutes |
| Backtest (5 years, 50 instruments) | < 30 minutes | 2 hours |
| Paper trade (per session) | 1–30 days | N/A (calendar-based) |
| Order placement latency | < 50ms | 500ms |
| Order fill confirmation | < 100ms | 1 second |
| Risk check (pre-trade) | < 10ms | 50ms |
| P&L calculation (per position) | < 100ms | 500ms |
| Market data processing latency | < 10ms | 100ms |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture — Trading domain structure |
| Physics/005-Events.md | Evidence — Trading operations produce Events |
| Physics/007-Capabilities.md | Capabilities — Trading capability bounds and risk limits |
| Physics/012-Experience.md | Experience — Trading outcomes drive strategy improvement |
| Bible/02-Core/Sou/002-Planner.md | Planner — Sou produces trading strategy research plans |
| Bible/02-Core/AGS/000-Overview.md | AGS — TradingWorker and ExecutionWorker Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy — Strategy and market model knowledge management |
| Bible/02-Core/DTS/000-Overview.md | DTS — Strategy confidence scoring and backtest validation |
| Bible/02-Core/ROS/000-Overview.md | ROS — Capital allocation and position sizing |
| Bible/06-Services/ACF/000-Overview.md | ACF — Market data and order transport |
| Bible/06-Services/Cryptography/KMS/000-KMS.md | KMS — Exchange credential management |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK — Exchange connectivity provider |
| Bible/08-Interfaces/API/000-Specifications.md | API — Market data API contract specifications |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
