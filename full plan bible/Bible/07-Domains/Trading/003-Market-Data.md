# AIOS Bible — Domains
## Trading — 003: Market Data

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-TRD-003 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Market Data domain manages the ingestion, normalization, validation, storage, real-time distribution, and historical retrieval of financial market data. It ensures data integrity through staleness detection, gap filling, and timestamp accuracy guarantees across all feeds and derived products.

## Architecture

```
Feed Connection
    |
    v
Protocol Parsing
    |
    v
Normalization
    |
    v
Validation
    |
    +--> Distribution (real-time)
    |
    +--> Archival (historical)
```

## Data Model (TypeScript)

```typescript
interface MarketDataFeed {
  id: string;
  exchange: string;
  protocol: "fix" | "websocket" | "rest" | "binary";
  symbols: string[];
  dataTypes: ("trade" | "quote" | "ohlcv" | "obook" | "news")[];
  status: "connecting" | "active" | "degraded" | "disconnected";
  latencyMs: number;
  connectedAt: Timestamp | null;
  lastHeartbeat: Timestamp | null;
}

interface TickRecord {
  id: string;
  symbol: string;
  exchange: string;
  price: number;
  volume: number;
  side: "buy" | "sell" | "unknown";
  timestamp: Timestamp;
  receivedAt: Timestamp;
  feedId: string;
}

interface OHLCVBar {
  symbol: string;
  exchange: string;
  timeframe: "1m" | "5m" | "15m" | "1h" | "4h" | "1d";
  open: number;
  high: number;
  low: number;
  close: number;
  volume: number;
  trades: number;
  openTimestamp: Timestamp;
  closeTimestamp: Timestamp;
  isClosed: boolean;
}

interface OrderBookSnapshot {
  symbol: string;
  exchange: string;
  bids: [number, number][];
  asks: [number, number][];
  timestamp: Timestamp;
  sequence: number;
  checksum: string;
}

interface DataValidationResult {
  feedId: string;
  symbol: string;
  valid: boolean;
  checks: ValidationCheck[];
  timestamp: Timestamp;
}

interface ValidationCheck {
  name: string;
  passed: boolean;
  detail: string;
}

interface FeedStatus {
  feedId: string;
  status: MarketDataFeed["status"];
  uptime: number;
  messagesReceived: number;
  messagesDropped: number;
  avgLatencyMs: number;
  lastError: string | null;
}
```

## Core Concepts / Operations

| Operation | Description | Input | Output |
|-----------|-------------|-------|--------|
| ingest_feed | Establish connection and begin consuming feed | feedConfig | MarketDataFeed |
| normalize_tick | Convert raw tick to canonical TickRecord | rawTick, feedId | TickRecord |
| validate_data | Run validation rules on incoming data point | dataPoint | DataValidationResult |
| build_ohlcv | Aggregate ticks into OHLCV bars | symbol, timeframe, ticks[] | OHLCVBar |
| maintain_orderbook | Apply tick to local order book | symbol, exchange, tick | OrderBookSnapshot |
| query_history | Retrieve historical data for a time range | symbol, from, to, dataType | DataPoint[] |

## Internal Interfaces

| Interface | Consumer | Description |
|-----------|----------|-------------|
| FeedManager | TradingWorker | Manages feed lifecycle and health |
| Normalizer | QuantWorker, RiskWorker | Converts raw data to canonical types |
| Validator | TradingWorker | Runs quality checks on data |
| OHLCVBuilder | QuantWorker | Produces bar data from tick stream |
| OrderBookManager | ExecutionWorker | Maintains real-time order book state |
| DataStore | All | Provides historical data access |

## Events

| Event Type | Produced When | Fields |
|-------|----------|---------|
| Trading.FeedConnected | FeedManager: feedId, exchange, symbols | Fired when a feed establishes connection |
| Trading.TickProcessed | Normalizer: tickId, symbol, exchange | Published for every normalized tick |
| Trading.BarClosed | OHLCVBuilder: symbol, timeframe, bar | Emitted when a bar period closes |
| Trading.DataQualityAlert | Validator: feedId, symbol, failedChecks[] | Fired when validation rules fail |
| Trading.FeedDegraded | FeedManager: feedId, reason, latencyMs | Published on latency or reliability degradation |
| Trading.FeedDisconnected | FeedManager: feedId, reason, lastSequence | Fired on unexpected disconnection |
| Trading.GapDetected | DataStore: symbol, fromTimestamp, toTimestamp, gapDuration | Emitted when a data gap is found |
| Trading.OrderBookUpdated | OrderBookManager: symbol, exchange, sequence, depth | Published on significant order book change |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| TRD-MKT-001 | Feed delivery delay exceeds configured latency SLA | MEDIUM | Alert ops, switch to secondary feed if available |
| TRD-MKT-002 | Data gap detected (missing ticks for gapDuration threshold) | MEDIUM | Fill via linear interpolation, flag gap in audit log |
| TRD-MKT-003 | Invalid tick received (price <= 0, NaN, overflow) | LOW | Drop tick, log validation failure |
| TRD-MKT-004 | Order book checksum mismatch on snapshot | HIGH | Request full order book refresh, discard incremental |
| TRD-MKT-005 | Feed disconnection with no secondary feed available | CRITICAL | Halt dependent algorithms, alert operator |
| TRD-MKT-006 | Timestamp drift exceeds 1 second between feed and system clock | MEDIUM | Apply drift correction, log warning |
| TRD-MKT-007 | Duplicate tick detected (same sequence/feed/symbol/timestamp) | LOW | Deduplicate by sequence number, log once |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| TRD-MKT-INV-001 | Every tick must have a monotonically increasing sequence number per feed-symbol pair | Precondition check in Normalizer; reject out-of-order ticks |
| TRD-MKT-INV-002 | Market data staleness must be detected within 2 seconds | Heartbeat monitor in FeedManager; alert on timeout |
| TRD-MKT-INV-003 | Gap filling methodology must be consistent per symbol and never use future data | Filled gaps stored with fill method metadata; forward-only constraint |
| TRD-MKT-INV-004 | All timestamps must use UTC with microsecond precision | Enforcement in Normalizer; reject non-UTC timestamps |
| TRD-MKT-INV-005 | Historical data query must return exactly-once semantics for overlapping time ranges | Deduplication key on (symbol, exchange, timestamp, sequence) |
| TRD-MKT-INV-006 | Order book bid-ask spread must never be negative | Integrity check after each book update; fail-fast |

## Design DNA (R1-R6,R9,R10,R13-R15)

- **R1 — Single Source of Truth**: The Normalizer is the sole producer of canonical TickRecords; consumers never interpret raw data.
- **R2 — Immutable Event Log**: Every tick, bar close, and validation event is written to the event log.
- **R3 — Capability-Based Authorization**: Only FeedManager capability may modify feed configuration or lifecycle.
- **R4 — Law of Diminishing Returns**: Historical data retention policies are tuned by the value density of each data type.
- **R5 — Deterministic Computation**: OHLCV bar construction produces identical bars from identical tick sequences.
- **R6 — Bounded Context**: Market Data owns feed ingestion and normalization; derived indicators belong to Algorithms.
- **R9 — Fail-Fast**: Invalid ticks and checksum failures are rejected immediately; never buffered for later validation.
- **R10 — Audit Trail**: Every feed status change, data gap, and quality alert is logged with full context.
- **R13 — Defensive Design**: On feed degradation, systems degrade gracefully using cached or secondary data sources.
- **R14 — Self-Healing**: On transient feed disconnection, automatic reconnection with sequence gap detection and replay.
- **R15 — Backward Compatibility**: Historical data schemas and query interfaces maintain versioned migration paths.

## Related Documents

- Bible/07-Domains/Trading/001-Algorithms.md
- Bible/07-Domains/Trading/002-Risk-Analysis.md
- Physics/005-Events.md
- Physics/007-Capabilities.md
- Physics/012-Experience.md
