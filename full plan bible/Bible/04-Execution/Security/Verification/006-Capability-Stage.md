# AIOS Bible — Security
## 006 — Capability Bounds Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-006 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Verify that the requested action stays within the entity's declared capability bounds — bounds checking, resource limits, capability scope.

## Architecture

```
Capability Request (entityId, action, resource, requestedResources)
        │
        ▼
┌────────────────────────────┐
│ Capability Bounds Retrieval│──► Fetch from CCA
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Action Scope Validation    │──► Is action within declared capabilities?
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Resource Limit Checking    │──► CPU, memory, network, tokens
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Capability Escalation      │──► Detect escalation attempts
│ Detection                  │
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Bounds Freeze Enforcement  │──► No bounds modification during execution
└───────────┬────────────────┘
            │
            ▼
       Capability Result
    (passed / exceeded)
```

## Data Model

```typescript
interface CapabilityDeclaration {
  entityId: string;
  capabilities: string[];
  resourceLimits: ResourceLimits;
  scope: string;
  version: string;
  declaredAt: Timestamp;
  signature: string;
}

interface CapabilityBounds {
  entityId: string;
  maxCPU: number;        // CPU cores
  maxMemory: number;     // MB
  maxBandwidth: number;  // Mbps
  maxTokens: number;     // tokens per period
  maxConcurrentOps: number;
  allowedActions: string[];
  allowedResources: string[];
  frozen: boolean;
  frozenAt: Timestamp | null;
}

interface CapabilityCheck {
  passed: boolean;
  bounds: CapabilityBounds | null;
  actionAllowed: boolean;
  resourcesWithinLimits: boolean;
  escalationDetected: boolean;
  checkTime: Timestamp;
  errorCode: string | null;
  evidenceRef: string | null;
}

interface ResourceLimits {
  cpu: number;
  memory: number;
  bandwidth: number;
  tokens: number;
  concurrentOps: number;
}

interface CapabilityAudit {
  auditId: string;
  entityId: string;
  action: string;
  requestedResources: ResourceLimits;
  actualResources: ResourceLimits;
  withinBounds: boolean;
  checkedAt: Timestamp;
}
```

## Core Concepts / Operations

- **Capability Bounds Retrieval from CCA**: Fetch the entity's declared capability bounds from the Capability and Capacity Architecture (CCA). Bounds are signed and versioned.
- **Resource Limit Checking**: Compare requested resources (CPU, memory, network bandwidth, tokens) against declared maximums. Exceeding any limit causes stage failure.
- **Action Scope Validation**: Verify the requested action is within the entity's declared capability scope. Unlisted actions are rejected.
- **Capability Bound Freeze Enforcement**: Capability bounds are frozen at execution start. No bounds modification is permitted during pipeline execution.
- **Capability Escalation Detection**: Detect attempts to perform actions that would escalate privileges beyond declared capabilities (e.g., modifying own bounds, granting capabilities to others).
- **Failure Modes**: Action outside bounds, resource limit exceeded, capability declaration missing.

## Internal Interfaces

```typescript
interface CapabilityStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface BoundsRetriever {
  getBounds(entityId: string): Promise<CapabilityBounds | null>;
  verifySignature(declaration: CapabilityDeclaration): Promise<boolean>;
}

interface ResourceLimitChecker {
  checkCPU(requested: number, max: number): boolean;
  checkMemory(requested: number, max: number): boolean;
  checkBandwidth(requested: number, max: number): boolean;
  checkTokens(requested: number, max: number): boolean;
  checkAll(requested: ResourceLimits, bounds: CapabilityBounds): boolean;
}

interface EscalationDetector {
  detect(entityId: string, action: string, resourceRef: string): Promise<boolean>;
  isCapabilityAction(action: string): boolean;
}

interface BoundsFreezer {
  freeze(entityId: string): Promise<void>;
  isFrozen(entityId: string): Promise<boolean>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.Cap.CapabilityBoundsRetrieved` | entityId, boundsVersion | Capability bounds fetched from CCA |
| `FV.Cap.ResourceLimitChecked` | entityId, cpu, memory, bandwidth, tokens | Resource limits evaluated against bounds |
| `FV.Cap.ScopeValidated` | entityId, action, allowed | Action within declared scope |
| `FV.Cap.CapabilityPassed` | entityId, action | All capability checks passed |
| `FV.Cap.CapabilityExceeded` | entityId, action, exceededResource | Capability bounds exceeded |
| `FV.Cap.EscalationDetected` | entityId, action | Capability escalation attempt detected |
| `FV.Cap.BoundsFreezeEnforced` | entityId, frozenAt | Capability bounds frozen for execution |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Action outside declared capabilities | `FV_CAP_001` | Stage failed; capability not declared |
| Resource limit exceeded | `FV_CAP_002` | Stage failed; resource request exceeds bounds |
| Capability declaration missing | `FV_CAP_003` | Stage failed; no capabilities registered |
| Escalation attempt detected | `FV_CAP_004` | Stage failed; escalate to Security Council |
| Capability bounds signature invalid | `FV_CAP_005` | Stage failed; bounds tampered |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-CAP-001 | Entity never exceeds its declared capability bounds for any resource type | Algorithmic — resource limit checks for all dimensions |
| FV-CAP-002 | Capability bounds are frozen and immutable during pipeline execution | Architectural — BoundsFreezer enforces at stage entry |
| FV-CAP-003 | Every capability declaration is signed and verifiable | Algorithmic — signature verification on retrieval |
| FV-CAP-004 | Capability escalation attempts are always detected and blocked | Architectural — EscalationDetector runs on every action |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Capability Stage owns bounds verification; CCA owns capability storage |
| R2 — Dependency Order | Depends on CCA for bounds; no circular dependencies |
| R3 — DRY | Capability bounds defined once in CCA; verified against, not duplicated |
| R4 — Builder Pattern | CapabilityCheck built from sub-checks |
| R9 — Deterministic | Same entity + same bounds = same capability result |
| R10 — Simpler Over Complex | Fixed resource dimensions; extensible via CCA schema |
| R13 — Design for Failure | Missing declaration blocks execution; escalation alerts council |
| R14 — Paved Path | Resource limits declared at entity registration; frozen at execution |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — capability integrity property |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — Capability is stage 5 |
| Bible/04-Execution/Security/Verification/005-Policy-Stage.md | Policy Stage — provides policy context for capability evaluation |
| Bible/04-Execution/Security/Verification/007-Risk-Stage.md | Risk Stage — next stage in pipeline |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA — capability bounds source and authority |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for capability checks |
