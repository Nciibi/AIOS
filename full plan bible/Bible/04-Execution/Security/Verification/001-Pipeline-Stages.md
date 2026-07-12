# AIOS Bible — Security
## 001 — Verification Pipeline Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-001 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Overall 7-stage verification pipeline architecture connecting all stages — pipeline orchestrator, stage coordination, token production.

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                   Verification Pipeline (7-Stage)                  │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Identity │─►│ AuthN    │─►│ AuthZ    │─►│ Policy   │          │
│  │ Stage    │  │ Stage    │  │ Stage    │  │ Stage    │          │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │
│                         │                                         │
│  ┌──────────┐  ┌──────────▼──────────┐  ┌──────────┐             │
│  │ Risk     │◄─│ Capability          │◄─│ Policy   │             │
│  │ Stage    │  │ Stage               │  │ Stage    │             │
│  └────┬─────┘  └─────────────────────┘  └──────────┘             │
│       │                                                           │
│  ┌────▼─────┐                                                     │
│  │ Final    │                                                     │
│  │ Auth     │                                                     │
│  │ Stage    │                                                     │
│  └────┬─────┘                                                     │
│       │                                                           │
│       ▼                                                           │
│  ┌──────────┐                                                     │
│  │  EAS     │                                                     │
│  │  Token   │                                                     │
│  └──────────┘                                                     │
└───────────────────────────────────────────────────────────────────┘
```

Pipeline orchestrator executes stages sequentially, short-circuiting on failure. Each stage enriches a shared PipelineContext. On success, an EASExecutionToken is produced and issued to the Runtime Engine.

## Data Model

```typescript
interface PipelineDef {
  pipelineId: string;
  name: string;
  stages: StageDef[];
  enabled: boolean;
  timeoutMs: number;
  maxRetries: number;
}

interface StageDef {
  stageId: string;
  name: 'identity' | 'authentication' | 'authorization' | 'policy' | 'capability' | 'risk' | 'final-authorization';
  order: number;
  enabled: boolean;
  timeoutMs: number;
  retryCount: number;
}

interface PipelineContext {
  pipelineId: string;
  requestId: string;
  entityId: string | null;
  action: string;
  resourceRef: string;
  stageResults: Map<string, StageResult>;
  startTime: Timestamp;
  endTime: Timestamp | null;
  aborted: boolean;
}

interface EASExecutionToken {
  tokenId: string;
  entityId: string;
  allowedActions: string[];
  resourceScope: string;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  signature: string;
  chainRef: string;
}

interface PipelineMetrics {
  pipelineId: string;
  stageLatencies: Map<string, number>;
  passCount: number;
  failCount: number;
  totalExecutions: number;
  bottleneckStage: string | null;
  reportedAt: Timestamp;
}

interface StageResult {
  stageId: string;
  passed: boolean;
  latencyMs: number;
  errorCode: string | null;
  evidenceRef: string | null;
}
```

## Core Concepts / Operations

- **Sequential Stage Execution**: Stages execute in order (Identity → AuthN → AuthZ → Policy → Capability → Risk → Authorization). Each stage receives PipelineContext and returns StageResult.
- **Short-Circuit on Failure**: If any stage fails, remaining stages are skipped and pipeline aborts with FV.Pipe.PipelineAborted.
- **Pipeline Context Propagation**: Shared state accumulates across stages. Stage results are stored in PipelineContext.stageResults for downstream consumers.
- **Execution Token Production**: On successful completion of all stages, the Final Authorization Stage produces a signed EASExecutionToken.
- **Stage-Level Timeout and Retry**: Each stage has configurable timeout and retry count. Timeouts are reported as stage failures.
- **Pipeline Metrics**: Per-stage latency, pass/fail rates, and bottleneck detection are collected and reported via FV.Pipe.PipelineMetricsReported.
- **Pipeline Configuration**: Stages can be individually enabled/disabled. Timeout per stage is configurable in PipelineDef.

## Internal Interfaces

```typescript
interface PipelineOrchestrator {
  execute(request: PipelineRequest): Promise<EASExecutionToken | null>;
  getMetrics(pipelineId: string): Promise<PipelineMetrics>;
  configure(def: PipelineDef): Promise<void>;
}

interface StageHandler {
  id: string;
  execute(context: PipelineContext): Promise<StageResult>;
}

interface PipelineContextStore {
  save(context: PipelineContext): Promise<void>;
  load(pipelineId: string): Promise<PipelineContext>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.Pipe.PipelineStarted` | pipelineId, requestId, entityId | Pipeline execution began |
| `FV.Pipe.StageEntered` | pipelineId, stageId, order | Stage handler invoked |
| `FV.Pipe.StageCompleted` | pipelineId, stageId, latencyMs | Stage completed successfully |
| `FV.Pipe.StageFailed` | pipelineId, stageId, errorCode, latencyMs | Stage failed |
| `FV.Pipe.PipelineCompleted` | pipelineId, tokenId | All stages passed, token issued |
| `FV.Pipe.PipelineAborted` | pipelineId, failedStageId | Pipeline short-circuited on failure |
| `FV.Pipe.TokenIssued` | tokenId, entityId, expiry | Execution token issued to entity |
| `FV.Pipe.TokenDenied` | pipelineId, entityId, reason | Token denied |
| `FV.Pipe.PipelineMetricsReported` | pipelineId, metrics | Metrics snapshot reported |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Stage not found | `FV_PIPE_001` | Abort pipeline; invalid configuration |
| Stage timeout exceeded | `FV_PIPE_002` | Mark stage failed; abort pipeline |
| Pipeline context corrupted | `FV_PIPE_003` | Abort pipeline; log critical error |
| Stage dependency missing | `FV_PIPE_004` | Abort pipeline; configuration error |
| Token generation failed | `FV_PIPE_005` | Abort pipeline; retry recommended |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-PIPE-001 | Stages execute in declared order — no stage may be skipped | Architectural — orchestrator enforces sequence |
| FV-PIPE-002 | Pipeline aborts on first stage failure — no partial tokens | Algorithmic — short-circuit on non-passing result |
| FV-PIPE-003 | Every pipeline execution produces an event log entry | Architectural — EVS logging on start and completion |
| FV-PIPE-004 | Token is never issued unless all 7 stages pass | Constitutional — Final Authorization Stage enforces |
| FV-PIPE-005 | Stage timeout never exceeds configured PipelineDef.timeoutMs | Algorithmic — timeout enforced per invocation |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Pipeline owns orchestration; each stage owns its verification domain |
| R2 — Dependency Order | Pipeline orchestrates stages; no circular stage dependencies |
| R3 — DRY | Shared context model reused across all stages |
| R4 — Builder Pattern | PipelineDef built via config builder; stages registered by ID |
| R9 — Deterministic | Same request + same pipeline config = same outcome |
| R10 — Simpler Over Complex | Sequential pipeline preferred over parallel for audit clarity |
| R13 — Design for Failure | Short-circuit prevents partial authorization |
| R14 — Paved Path | All stages enabled by default; selective disable via RFC |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — pipeline is the verification target |
| Bible/04-Execution/Security/Verification/002-Identity-Stage.md | Identity Stage — stage 1 handler |
| Bible/04-Execution/Security/Verification/003-AuthN-Stage.md | Authentication Stage — stage 2 handler |
| Bible/04-Execution/Security/Verification/004-AuthZ-Stage.md | Authorization Stage — stage 3 handler |
| Bible/04-Execution/Security/Verification/005-Policy-Stage.md | Policy Stage — stage 4 handler |
| Bible/04-Execution/Security/Verification/006-Capability-Stage.md | Capability Stage — stage 5 handler |
| Bible/04-Execution/Security/Verification/007-Risk-Stage.md | Risk Stage — stage 6 handler |
| Bible/04-Execution/Security/Verification/008-Authorization-Stage.md | Final Authorization Stage — stage 7 handler |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | EAS — consumes execution tokens from pipeline |
| Bible/04-Execution/Security/IDS/001-Registry.md | IDS — identity records consumed by Identity Stage |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA — capability bounds consumed by Capability Stage |
| Bible/06-Services/Cryptography/000-CSP.md | CSP — token signing and signature verification |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for all pipeline events |
