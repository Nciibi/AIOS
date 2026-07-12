# AIOS Bible — Security
## 007 — Risk Assessment Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-007 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Assess the risk level of the requested action — risk scoring, historical context, anomaly detection.

## Architecture

```
Risk Assessment Request (entityId, action, resource, context)
        │
        ▼
┌────────────────────────────┐
│ Risk Factor Computation    │──► Action type, resource sensitivity,
│                            │    entity history, time patterns
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Historical Context Load    │──► Past violations, frequency,
│                            │    similar action patterns
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Anomaly Detection          │──► Deviation from entity baseline,
│                            │    unusual patterns
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Risk Level Assignment      │──► Low / Medium / High / Critical
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Risk-Based Action          │──► Allow / Log / Flag / Block
│ Decision                   │
└───────────┬────────────────┘
            │
            ├── Low ──────────► Allow
            ├── Medium ───────► Log + Allow
            ├── High ─────────► Flag + Allow (with monitoring)
            └── Critical ─────► Block (escalate to Security Council)
```

## Data Model

```typescript
interface RiskScore {
  overallScore: number;      // 0.0 (lowest) - 1.0 (highest)
  factorScores: Record<string, number>;
  computedAt: Timestamp;
}

interface RiskFactors {
  actionRisk: number;        // Risk inherent to action type
  resourceSensitivity: number;
  entityHistoryScore: number;
  timeAnomalyScore: number;
  geoAnomalyScore: number;
  frequencyScore: number;
}

interface HistoricalContext {
  entityId: string;
  pastViolations: number;
  totalActions: number;
  violationRate: number;
  lastViolationAt: Timestamp | null;
  similarActionFrequency: number;
  averageRiskScore: number;
}

interface AnomalyIndicator {
  anomalous: boolean;
  anomalyType: 'time' | 'geo' | 'frequency' | 'resource' | 'sequence' | null;
  deviationScore: number;
  description: string | null;
}

interface RiskLevel {
  level: 'low' | 'medium' | 'high' | 'critical';
  threshold: number;
  action: 'allow' | 'log' | 'flag' | 'block';
  escalated: boolean;
  escalatedTo: string | null;
}

interface RiskAssessmentResult {
  passed: boolean;
  riskScore: RiskScore | null;
  riskLevel: RiskLevel | null;
  anomaly: AnomalyIndicator | null;
  historicalContext: HistoricalContext | null;
  errorCode: string | null;
  evidenceRef: string | null;
}
```

## Core Concepts / Operations

- **Risk Scoring Factors**: Action type (destructive actions score higher), resource sensitivity (classified data scores higher), entity history (past violations increase score), time patterns (off-hours access scores higher).
- **Historical Context**: Load entity's action history — past violations, frequency of similar actions, average risk score over time.
- **Anomaly Detection**: Detect deviation from entity's baseline behavior — unusual access times, geographic anomalies, abnormal frequency spikes, unusual action sequences.
- **Risk Level Classification**: Map composite risk score to level: low (0.0–0.25), medium (0.25–0.50), high (0.50–0.75), critical (0.75–1.0).
- **Risk-Based Action**: Based on risk level: low = allow, medium = log + allow, high = flag + allow with monitoring, critical = block + escalate to Security Council.
- **Integration with Security Council**: High-risk decisions optionally forwarded to Security Council for manual override.
- **Failure Modes**: Risk engine timeout, insufficient historical data.

## Internal Interfaces

```typescript
interface RiskStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface RiskScorer {
  compute(entityId: string, action: string, resourceRef: string, context: Record<string, unknown>): Promise<RiskScore>;
  getFactorWeights(): Record<string, number>;
}

interface HistoryLoader {
  load(entityId: string): Promise<HistoricalContext>;
  getSimilarActions(entityId: string, action: string, windowHours: number): Promise<number>;
}

interface AnomalyDetector {
  detect(entityId: string, action: string, context: Record<string, unknown>): Promise<AnomalyIndicator>;
  getBaseline(entityId: string): Promise<Record<string, unknown>>;
}

interface RiskLevelMapper {
  classify(score: RiskScore): RiskLevel;
  getThresholds(): Record<string, number>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.Risk.RiskAssessmentStarted` | entityId, action | Risk assessment initiated |
| `FV.Risk.RiskFactorComputed` | factorName, score | Individual risk factor scored |
| `FV.Risk.HistoricalContextLoaded` | entityId, pastViolations, totalActions | Entity history retrieved |
| `FV.Risk.AnomalyDetected` | anomalyType, deviationScore | Behavioral anomaly identified |
| `FV.Risk.RiskLevelAssigned` | level, score, action | Risk level classified |
| `FV.Risk.RiskAccepted` | entityId, riskLevel | Risk accepted; action proceeds |
| `FV.Risk.RiskEscalated` | entityId, riskLevel | Escalated to Security Council |
| `FV.Risk.RiskAssessmentCompleted` | entityId, riskLevel, decision | Assessment finalized |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Risk engine timeout | `FV_RISK_001` | Stage failed; default to deny |
| Insufficient historical data | `FV_RISK_002` | Stage passed with elevated risk score |
| Anomaly detection unavailable | `FV_RISK_003` | Stage passed; anomaly score defaulted to zero |
| Risk factor computation error | `FV_RISK_004` | Stage failed; computation error |
| Security Council escalation failure | `FV_RISK_005` | Stage failed; escalation required but unavailable |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-RISK-001 | Risk score always maps to a defined risk level and action | Algorithmic — RiskLevelMapper covers full 0.0–1.0 range |
| FV-RISK-002 | Critical risk actions are always blocked unless overridden by Security Council | Constitutional — escalation is mandatory |
| FV-RISK-003 | Anomaly detection compares against entity baseline, not global average | Algorithmic — baseline per entity |
| FV-RISK-004 | Risk assessment never produces false negatives for critical-level threats | Algorithmic — conservative scoring for boundary cases |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Risk Stage owns risk assessment; Security Council owns override authority |
| R2 — Dependency Order | Depends on HistoryLoader, AnomalyDetector, RiskScorer |
| R3 — DRY | Risk factors computed once; scoring formula is centralized |
| R4 — Builder Pattern | RiskAssessmentResult aggregates scores, context, anomaly |
| R9 — Deterministic | Same entity + same history + same action = same risk score |
| R10 — Simpler Over Complex | Fixed risk factors with configurable weights |
| R13 — Design for Failure | Timeout defaults to deny; escalation failure blocks action |
| R14 — Paved Path | Risk-based logging for medium; flag for high; block for critical |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — risk invariants |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — Risk is stage 6 |
| Bible/04-Execution/Security/Verification/006-Capability-Stage.md | Capability Stage — provides capability context for risk evaluation |
| Bible/04-Execution/Security/Verification/008-Authorization-Stage.md | Final Authorization Stage — next stage in pipeline |
| Bible/04-Execution/Security/000-Overview.md | Security Council — escalation target for critical risks |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for risk assessments |
