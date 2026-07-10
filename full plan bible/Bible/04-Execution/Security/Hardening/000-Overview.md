# AIOS Bible — Security
## Hardening — 000: Security Hardening

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Hardening |
| Document ID | AIOS-BBL-004-SHD-000 |
| Source Laws | Law 8 — Law of Verification-First, Law 5 — Law of Identity, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Security Hardening is the discipline of making AIOS resistant to attack by default. It is the operational counterpart to the Security Kernel's verification pipeline — where the Kernel *enforces* security at runtime, Hardening *reduces the attack surface* and *raises the cost of compromise* across the entire platform. Hardening is defense-in-depth: every subsystem is configured with secure defaults, least privilege, and continuous monitoring so that a single failure does not become a full breach.

Hardening is not a one-time activity. It is a continuous process driven by the threat model, validated by penetration testing (Pentest), and proven by formal verification (Verification). This document defines the hardening baseline, the components that enforce it, and the invariants that must hold.

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                 Security Hardening                      │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Threat Model │  │ Baseline     │  │  Hardening   │  │
│  │  Registry    │  │  Manager     │  │  Engine      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │          │
│         └─────────────────┼─────────────────┘          │
│                           │                            │
│                  ┌────────▼────────┐                   │
│                  │  Audit & Report │                   │
│                  │  (findings)     │                   │
│                  └────────┬────────┘                   │
└───────────────────────────┼────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │  Security  │  │  Subsystems│  │  Runtime   │
     │  Kernel    │  │  (CCA,..)  │  │  /Sandbox  │
     └────────────┘  └────────────┘  └────────────┘
```

## Core Concepts

### 1. Threat Model

A living description of what AIOS defends against: adversary types (external attacker, compromised insider, malicious agent, supply-chain), attack vectors (identity forgery, capability escalation, message injection, resource exhaustion), and impact classes (confidentiality, integrity, availability, constitutional violation). The Threat Model Registry stores current threats and their mitigations.

### 2. Defense in Depth

No single control is sufficient. AIOS layers controls so that the failure of one does not compromise the whole: Identity (IRS) → Authentication (ATS) → Authorization (AZS) → Policy (Policy-System) → Capability (CCA) → Risk (Risk Engine) → Execution Authorization (EAS) → Audit (AUS). Hardening ensures each layer is configured to its strongest setting.

### 3. Secure Defaults

Every subsystem ships with the most restrictive safe configuration: deny-by-default policies, minimal capability grants, short token lifetimes, encryption at rest and in transit, and disabled debug interfaces. Secure defaults are non-negotiable — relaxing them requires explicit, logged, and reviewed change.

### 4. Least Privilege

Entities receive the minimum capabilities, autonomy level, and resource budget required for their function. Hardening enforces least privilege at creation (AGS templates) and continuously reviews for privilege creep (AGX monitors agents for capability expansion beyond need).

### 5. Attack Surface Reduction

Minimizing what is exposed: only necessary ACF endpoints are published, debug and admin interfaces require elevated identity, unused capabilities are pruned from genomes, and external network access is sandboxed. The Sandbox subsystem isolates untrusted execution.

### 6. Hardening Baseline

The canonical set of hardening controls applied across all subsystems: TLS-only transport, signed genomes (AGS), immutable audit logs, rate-limited auth, sealed secrets (Crypto), and verified boot (TEE). The Baseline Manager distributes and validates the baseline.

### 7. Continuous Hardening

Hardening is monitored continuously: drift from baseline is detected, new threats trigger baseline updates via RFC, and penetration test findings feed remediation. Hardening status is reported to the Dashboard and escalated via the Governance Console when a control fails.

## Data Model

```typescript
interface ThreatModel {
  threatId: string;
  name: string;
  adversaryType: 'external' | 'insider' | 'agent' | 'supply-chain';
  vector: string;
  impact: 'confidentiality' | 'integrity' | 'availability' | 'constitutional';
  likelihood: 'low' | 'medium' | 'high';
  mitigationRefs: string[];  // references to controls
  status: 'active' | 'mitigated' | 'accepted';
}

interface HardeningBaseline {
  baselineId: string;
  name: string;
  version: number;
  controls: HardeningControl[];
  applicableTo: string[];  // subsystem or component IDs
  enforcedAt: Timestamp;
}

interface HardeningControl {
  controlId: string;
  name: string;
  category: 'identity' | 'auth' | 'crypto' | 'network' | 'runtime' | 'audit';
  requirement: string;
  verificationMethod: 'config-check' | 'pentest' | 'formal-proof';
  status: 'compliant' | 'drift' | 'failed';
}

interface HardeningFinding {
  findingId: string;
  controlId: string;
  subsystemId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  remediation: string;
  status: 'open' | 'in-progress' | 'resolved';
  evidenceRef: string;
}
```

## Interfaces

### Security Hardening API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `getBaseline(baselineId)` | Security Council | Retrieve current hardening baseline |
| `applyBaseline(targetId, baselineId)` | Security Council | Apply baseline to a subsystem |
| `checkCompliance(targetId)` | Security Council | Verify subsystem against baseline |
| `reportFinding(finding)` | Pentest, Audit | Record a hardening gap |
| `listThreats(filter)` | Security Council | List active threat models |
| `updateThreat(threatId, changes)` | Security Council | Update threat model via RFC |
| `getHardeningStatus()` | Any authenticated | Aggregate hardening compliance status |

### Internal Interfaces

```typescript
interface BaselineManager {
  distribute(baseline: HardeningBaseline): Promise<void>;
  validate(targetId: string, baseline: HardeningBaseline): Promise<ComplianceReport>;
  detectDrift(targetId: string): Promise<HardeningControl[]>;
}

interface ThreatRegistry {
  register(threat: ThreatModel): Promise<void>;
  list(active: boolean): Promise<ThreatModel[]>;
  linkControl(threatId: string, controlId: string): Promise<void>;
}

interface HardeningEngine {
  scan(targetId: string): Promise<HardeningFinding[]>;
  remediate(findingId: string, action: string): Promise<void>;
  escalate(finding: HardeningFinding): Promise<void>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Baseline Manager | Distributes and validates the hardening baseline across subsystems |
| Threat Registry | Maintains the living threat model |
| Hardening Engine | Scans for drift, reports findings, drives remediation |
| Audit & Report | Records hardening status; feeds Dashboard and Console |
| Crypto Integration | Enforces sealed secrets, signed artifacts, encryption |

## Data Flow

```
Threat model updated (RFC)
        │
        ▼
Baseline Manager updates baseline
        │
        ▼
Baseline distributed to subsystems
        │
        ▼
Hardening Engine scans for compliance
        │
        ├── Compliant ──► Status reported green
        │
        └── Drift/Failed ──► Finding created
                                │
                                ▼
                        Remediation tracked
                                │
                                ├── Resolved ──► Status green
                                │
                                └── Critical ──► Escalate to Console
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `SHD.BaselineApplied` | baselineId, targetId, version | Hardening baseline applied to subsystem |
| `SHD.ComplianceChecked` | targetId, compliant, driftCount | Compliance scan completed |
| `SHD.DriftDetected` | targetId, controlId, expected, actual | Baseline drift found |
| `SHD.FindingReported` | findingId, severity, subsystemId | Hardening gap recorded |
| `SHD.FindingResolved` | findingId, remediation | Gap remediated |
| `SHD.ThreatUpdated` | threatId, status | Threat model changed |
| `SHD.Escalated` | findingId, reason | Critical finding escalated to Console |
| `SHD.CriticalControlFailed` | controlId, subsystemId | A critical hardening control failed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Baseline not found | `SHD_BASELINE_NOT_FOUND` | Return error; no application |
| Subsystem not enrolled | `SHD_TARGET_NOT_ENROLLED` | Reject; subsystem must be enrolled first |
| Drift exceeds threshold | `SHD_DRIFT_CRITICAL` | Create critical finding; escalate |
| Finding evidence missing | `SHD_EVIDENCE_MISSING` | Reject; findings require evidence ref |
| Unauthorized baseline change | `SHD_UNAUTHORIZED_CHANGE` | Reject; only Security Council via RFC |
| Scan timeout | `SHD_SCAN_TIMEOUT` | Return partial; flag incomplete |
| Crypto seal broken | `SHD_SEAL_BROKEN` | Critical; isolate subsystem, alert |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SHD-001 | Every subsystem conforms to the current hardening baseline | Algorithmic — Baseline Manager validates on deploy |
| SHD-002 | Baseline changes require RFC approval (Law 9) | Constitutional — only Security Council via RFC |
| SHD-003 | Secure defaults are deny-by-default | Architectural — Policy-System enforces default-deny |
| SHD-004 | Every hardening finding references evidence (Law 4) | Architectural — findings require evidenceRef |
| SHD-005 | Critical control failure isolates the subsystem | Algorithmic — Hardening Engine triggers isolation |
| SHD-006 | Drift from baseline is always detected within scan interval | Algorithmic — scheduled scans with max interval |
| SHD-007 | Crypto seals are verified before artifact use | Architectural — Crypto verifies seals on load |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Hardening owns baseline enforcement; Security Kernel owns runtime enforcement |
| R2 — Dependency Order | Depends on CCA, AZS, Policy-System, Crypto, AUS; no cycles |
| R3 — DRY | Hardening controls defined once in baseline; subsystems reference, not duplicate |
| R4 — Builder Pattern | Baselines use builder for control composition per subsystem |
| R9 — Deterministic | Same baseline + same subsystem = same compliance result |
| R10 — Simpler Over Complex | Default deny-by-default baseline covers most cases; exceptions opt-in |
| R13 — Design for Failure | Drift and critical failures isolate and escalate, never silently pass |
| R14 — Paved Path | Standard baseline applied to all subsystems by default |
| R15 — Open/Closed | New control types register via Baseline Manager extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/000-Overview.md | Security Council — overall security architecture |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | EAS — runtime verification pipeline hardened by baseline |
| Bible/04-Execution/Security/IDS/001-Registry.md | IDS — identity is the first hardening layer |
| Bible/04-Execution/Security/AZS/002-Capability.md | AZS — authorization least-privilege enforcement |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA — capability bounds enforced as hardening control |
| Bible/04-Execution/Security/Policy-System/000-PS.md | Policy-System — default-deny policy enforcement |
| Bible/04-Execution/Security/Pentest/000-Overview.md | Pentest — validates hardening via offensive testing |
| Bible/04-Execution/Security/Verification/000-Overview.md | Verification — proves hardening properties formally |
| Bible/06-Services/Cryptography/000-Overview.md | Crypto — seals, signing, encryption controls |
| Bible/05-Platform/005-AUS.md | AUS — immutable audit of hardening status |
| Bible/05-Platform/004-EVS.md | EVS — evidence for all hardening findings |
| Physics/008-Security.md | Security invariants — hardening enforces these |
| Physics/005-Events.md | Evidence invariants — findings are logged |
