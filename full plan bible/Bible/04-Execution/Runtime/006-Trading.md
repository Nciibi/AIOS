# AIOS Bible — Execution
## 006 — Trading Execution Provider

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-006 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Trading Provider executes financial market operations — order placement, market data queries, portfolio management, and risk checks — through broker API integrations. Every execution is bounded by strict financial limits, verified by the token scope, and fully recorded for audit and compliance. The provider does not make trading decisions; it executes pre-verified, authorized actions.

## Capability Declaration

| Property | Value |
|----------|-------|
| provider_id | `aios.provider.trading` |
| action_types | `trading.order`, `trading.market_data`, `trading.portfolio`, `trading.risk_check`, `trading.account` |
| max_parallelism | 10 concurrent executions |
| default_timeout_ms | 30000 (30 seconds) |
| supported_autonomy_levels | L0, L1, L2 |

## Action Types

| Action Type | Description | Parameters |
|-------------|-------------|------------|
| `trading.order` | Place, modify, or cancel an order | symbol, side (buy/sell), type (market/limit/stop), quantity, price, time_in_force |
| `trading.market_data` | Fetch market data for instruments | symbols, data_type (quote/bars/trades/orderbook), timeframe, limit |
| `trading.portfolio` | Query portfolio positions and holdings | include_pnl, include_risk_metrics |
| `trading.risk_check` | Run pre-trade risk validation against portfolio | order_params, portfolio_snapshot |
| `trading.account` | Query account balance, margin, and trading permissions | account_id |

## Order Execution Flow

1. Provider receives a `trading.order` action with a verified execution token
2. Provider validates the order parameters against the token's capability bounds (max order size, allowed symbols, order types)
3. Provider performs a pre-trade risk check against the portfolio (position size, concentration, buying power)
4. Provider submits the order to the configured broker API (REST or FIX protocol)
5. Provider monitors order lifecycle (pending → filled/partially_filled → cancelled → rejected)
6. Provider returns order execution details including fill price, quantity, commission, and order ID
7. If the order is rejected by the broker, the provider returns a structured error with rejection reason

## Broker Abstraction

The provider supports multiple broker backends through a pluggable adapter interface:

| Adapter | Protocol | Supported Order Types |
|---------|----------|----------------------|
| Alpaca | REST + WebSocket | Market, Limit, Stop, StopLimit, TrailingStop |
| IBKR | TWS API / FIX | All order types |
| Tradier | REST | Market, Limit, Stop |
| Simulated | In-memory | Market, Limit (for backtesting and dry-run) |

The broker adapter is selected at provider configuration time. Dry-run mode uses the Simulated adapter regardless of the configured broker.

## Risk Boundaries

The provider enforces hard limits that cannot be exceeded regardless of the execution token's bounds:

| Bound | Default | Source |
|-------|---------|--------|
| Max single order value | $100,000 | Provider configuration |
| Max daily notional | $1,000,000 | Capability bounds |
| Max position concentration | 25% of portfolio | Provider configuration |
| Allowed instruments | Equity, ETF, Crypto (per config) | Provider configuration |
| Trading hours only | Configurable | Provider configuration |
| Minimum order interval | 1 second | Provider configuration |

## Error Handling

| Error Code | Condition | Action |
|------------|-----------|--------|
| TRD-0001 | Order exceeds max single order value | Deny; return max_allowed value |
| TRD-1001 | Insufficient buying power | Deny; return available buying power |
| TRD-2001 | Symbol not in allowed instrument list | Deny; return allowed symbols |
| TRD-3001 | Broker API unavailable | Return Unhealthy; queue order for retry (max 3 attempts) |
| TRD-4001 | Market closed | Deny; return next market open time |
| TRD-5001 | Order rejected by broker | Return rejection reason and broker error code |

## Events

| Event Type | Fields |
|------------|--------|
| `Provider.Trading.OrderSubmitted` | execution_id, symbol, side, order_type, quantity, limit_price |
| `Provider.Trading.OrderFilled` | execution_id, order_id, fill_price, fill_quantity, commission, timestamp |
| `Provider.Trading.OrderCancelled` | execution_id, order_id, cancelled_quantity, reason |
| `Provider.Trading.OrderRejected` | execution_id, order_id, rejection_reason, broker_code |
| `Provider.Trading.MarketDataReceived` | execution_id, symbol_count, data_type, record_count |
| `Provider.Trading.PortfolioQueried` | execution_id, position_count, total_value, cash_balance |
| `Provider.Trading.RiskCheckPassed` | execution_id, order_value, portfolio_value, concentration_pct |
| `Provider.Trading.RiskCheckFailed` | execution_id, risk_rule, threshold_value, actual_value |

## Cross-Cutting Concerns

### Security

API credentials (API keys, OAuth tokens) are resolved through the Runtime Manager's secret store. The provider validates that every order's symbol, side, and quantity are within the token's capability bounds. Trading is restricted to L0–L2 autonomy levels — no autonomous trading without explicit pre-authorization. All orders are logged with full detail for compliance audit.

### Evidence

Every order produces a complete Event chain: OrderSubmitted → OrderFilled/OrderCancelled/OrderRejected. Market data and portfolio queries produce snapshot Events. Risk checks produce Passed/Failed Events with the specific risk rule and values. Events include all order parameters for regulatory compliance.

### Lifecycle

The provider maintains persistent connections to broker APIs (WebSocket for real-time data, REST for order placement). On `initialize()`, it validates broker credentials and account permissions. On `shutdown()`, it cancels pending orders (if configured) and closes all connections.

### Capability Bounds

The provider enforces: max order value, max daily notional, allowed symbols, allowed order types, trading hours, minimum order interval, max position concentration, and max open orders. All bounds are checked before any broker API call.

### Communication

The provider communicates with broker APIs over encrypted connections (REST/HTTPS, WebSocket/WSS, or FIX over TLS). Provider-to-Runtime communication uses the SDK interface. Market data streams are consumed through broker WebSocket connections and relayed through the provider's streaming interface.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 | Provider handles financial execution only — no data analysis, no model inference |
| R5 | Broker adapters are interchangeable; Simulated adapter enables testability |
| R10 | Order execution is a linear pipeline: validate → risk check → submit → monitor → return |
| R12 | Every trading error has a unique TRD-NNNN code for compliance tracking |
| R13 | Broker API failures trigger retry with backoff; market closure denies execution (fail-closed) |
| R14 | Paved path: validate bounds → risk check → submit → record → return. No alternative execution path |
| R15 | New broker adapters implement the BrokerAdapter interface without modifying the provider |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime Engine architecture |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK used to build this provider |
| Physics/010-Execution.md | Execution invariants for financial operations |
| Physics/007-Capabilities.md | Capability bounds for trading limits and instrument scope |
