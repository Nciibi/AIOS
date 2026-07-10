# AIOS Bible — Security
## Verification — 000: Formal Verification

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-000 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Formal Verification provides mathematical proof that AIOS's security-critical properties hold. Where Penetration Testing demonstrates resilience empirically and Hardening configures defenses, Formal Verification *proves* — using model checking, theorem proving, and static analysis — that specific invariants cannot be violated under any execution. It is the highest-assurance tier of the verification hierarchy.

Formal Verification targets the properties that must hold absolutely: non-bypassability of the Security Kernel, identity uniqueness, capability-bound integrity, and constitutional compliance. A verified property carries a proof artifact (not just a test result) that can be independently checked. Verification results are evidence (Law 4) and feed the audit trail.

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                 Formal Verification                     │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Property    │  │  Verification │  │  Proof       │  │
│  │  Registry    │  │  Engine      │  │  Store       │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │          │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐  │
│  │  Model       │  │  Theorem     │  │  Static      │  │
│  │  Checker     │  │  Prover      │  │  Analyzer    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└────────────────────────────────────────────────────────┘
            │                      │              │
            ▼                      ▼              ▼
     ┌──────────┐          ┌──────────┐    ┌──────────┐
     │  Target  │          │  Proof   │    │  EVS     │
     │  Systems │          │  Artifacts│   │ (evidence)│
     └──────────┘          └──────────┘    └──────────┘
```

## Core Concepts

### 1. Verification Targets

The specific subsystems or properties under proof: the Security Kernel verification pipeline (identity→auth→authz→policy→capability→risk→execution), the IDS uniqueness invariant, CCA capability-bound integrity, and constitutional compliance checks. Targets are registered with the Property Registry.

### 2. Security Properties

The invariants being proven:
- **Non-bypassability**: No execution path skips any stage of the Security Kernel pipeline.
- **Identity Uniqueness**: No two active entities share an identity (IRS invariant).
- **Capability Integrity**: No Worker exceeds its declared capability bounds (CCA invariant).
- **Confidentiality**: Messages are readable only by authorized recipients (ACF invariant).
- **Constitutional Compliance**: No verified operation violates the Constitution.

### 3. Proof Methods

- **Model Checking**: Exhaustively explores the state space of a target (e.g., the verification pipeline state machine) to confirm a property holds in all reachable states.
- **Theorem Proving**: Constructs a logical proof (e.g., in Coq or Isabelle) that a property follows from the system's formal specification.
- **Static Analysis**: Analyzes code/configuration without execution to detect violations (e.g., capability over-grants, policy contradictions).

### 4. Proof Artifacts

The output of verification: a machine-checkable proof (model-checking certificate, theorem proof script, or static-analysis report) plus metadata (target version, tool version, property ID, timestamp). Artifacts are stored in the Proof Store and referenced by evidence.

### 5. Continuous Verification

Verification is re-run when targets change (RFC, new capability, kernel update). A regression (a previously-proven property now fails) blocks the change and alerts the Security Council. Continuous verification ensures proofs stay valid as the system evolves.

### 6. Property Registry

The authoritative list of security properties, their formal statements, the proof method, current proof status, and links to proof artifacts. The registry is the single source of truth for "what is proven."

## Data Model

```typescript
interface SecurityProperty {
  propertyId: string;
  name: string;
  formalStatement: string;  // logical formula
  category: 'non-bypassability' | 'identity' | 'capability' | 'confidentiality' | 'constitutional';
  targetRef: string;  // subsystem or component ID
  proofMethod: 'model-checking' | 'theorem-proving' | 'static-analysis';
  status: 'unproven' | 'proven' | 'regressed' | 'expired';
}

interface ProofArtifact {
  artifactId: string;
  propertyId: string;
  method: 'model-checking' | 'theorem-proving' | 'static-analysis';
  tool: string;  // e.g., TLA+, Coq, Infer
  toolVersion: string;
  targetVersion: string;  // version of verified target
  result: 'proved' | 'failed' | 'inconclusive';
  artifactRef: string;  // location of proof artifact
  verifiedAt: Timestamp;
  evidenceRef: string;
}

interface VerificationRun {
  runId: string;
  propertyId: string;
  method: string;
  status: 'running' | 'proved' | 'failed' | 'inconclusive';
  durationMs: number;
  artifactId: string | null;
  startedAt: Timestamp;
  completedAt: Timestamp | null;
}

interface RegressionAlert {
  alertId: string;
  propertyId: string;
  previousStatus: string;
  currentStatus: string;
  changeRef: string;  // RFC or commit that caused regression
  severity: 'high' | 'critical';
  evidenceRef: string;
}

interface VerifiedTarget {
  targetId: string;
  targetType: 'security-kernel' | 'ids' | 'cca' | 'acf' | 'subsystem';
  version: string;
  formalModel: string;  // reference to the target's formal model
}

interface CheckResult {
  propertyId: string;
  holds: boolean;
  exploredStates: number;
  counterexample: string | null;
}

interface StateSpace {
  targetId: string;
  stateCount: number;
  reachableStates: number;
  exploredAt: Timestamp;
}

interface FormalSpec {
  specId: string;
  propertyId: string;
  logic: 'first-order' | 'temporal' | 'propositional';
  formula: string;
}

interface ProofResult {
  propertyId: string;
  proved: boolean;
  proofScriptRef: string;
  assumptions: string[];
}
```

## Interfaces

### Formal Verification API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `registerProperty(property)` | Security Council | Register a security property for proof |
| `verify(propertyId, method)` | Security Council | Run verification for a property |
| `getProofArtifact(artifactId)` | Any authenticated | Retrieve a proof artifact |
| `listProperties(filter)` | Any authenticated | List registered properties and status |
| `checkRegression(changeRef)` | Security Council | Re-verify all properties affected by a change |
| `revokeProof(propertyId, reason)` | Security Council | Mark a property as regressed/expired |

### Internal Interfaces

```typescript
interface VerificationEngine {
  run(property: SecurityProperty, method: string): Promise<VerificationRun>;
  checkRegression(changeRef: string): Promise<RegressionAlert[]>;
}

interface ModelChecker {
  check(property: SecurityProperty, target: VerifiedTarget): Promise<CheckResult>;
  explore(target: VerifiedTarget): Promise<StateSpace>;
}

interface TheoremProver {
  prove(property: SecurityProperty, spec: FormalSpec): Promise<ProofResult>;
  validate(artifact: ProofArtifact): Promise<boolean>;
}

interface ProofStore {
  save(artifact: ProofArtifact): Promise<string>;
  retrieve(artifactId: string): Promise<ProofArtifact>;
  linkToEvidence(artifactId: string, evidenceRef: string): Promise<void>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Property Registry | Authoritative list of security properties and proof status |
| Verification Engine | Orchestrates verification runs across methods |
| Model Checker | Exhaustive state-space exploration for properties |
| Theorem Prover | Logical proof construction and validation |
| Static Analyzer | Code/configuration analysis for violations |
| Proof Store | Persists and links proof artifacts to evidence |

## Data Flow

```
Security property registered (RFCs)
        │
        ▼
Verification Engine selects method
        │
        ├── Model Checking ──► Model Checker explores state space
        │
        ├── Theorem Proving ──► Theorem Prover constructs proof
        │
        └── Static Analysis ──► Analyzer scans code/config
        │
        ▼
Proof artifact produced
        │
        ├── Proved ──► Stored + linked to evidence + status: proven
        │
        └── Failed ──► Regression alert + block change
        │
        ▼
On system change: re-verify affected properties (continuous)
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.PropertyRegistered` | propertyId, category, targetRef | Security property registered |
| `FV.VerificationStarted` | runId, propertyId, method | Verification run began |
| `FV.Proved` | runId, propertyId, artifactId | Property proven |
| `FV.ProofFailed` | runId, propertyId, reason | Property could not be proven |
| `FV.ArtifactStored` | artifactId, propertyId, tool | Proof artifact persisted |
| `FV.RegressionDetected` | alertId, propertyId, changeRef | Previously-proven property now fails |
| `FV.RegressionBlocked` | changeRef, properties | Change blocked by regression |
| `FV.ProofRevoked` | propertyId, reason | Proof marked invalid/expired |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Property not registered | `FV_PROPERTY_NOT_FOUND` | Reject; register first |
| Unsupported proof method | `FV_METHOD_UNSUPPORTED` | Reject; use registered method |
| Verification run timeout | `FV_RUN_TIMEOUT` | Mark inconclusive; allow retry |
| Proof artifact missing | `FV_ARTIFACT_MISSING` | Reject; artifact must be stored |
| Regression on critical property | `FV_CRITICAL_REGRESSION` | Block change; escalate to Console |
| Target version mismatch | `FV_TARGET_MISMATCH` | Reject; verify against current target version |
| Unauthorized property change | `FV_UNAUTHORIZED` | Reject; only Security Council via RFC |
| Proof validation failed | `FV_PROOF_INVALID` | Mark property unproven; re-run required |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-001 | Every proven property has a stored, checkable proof artifact | Architectural — Proof Store requires artifact on prove |
| FV-002 | Proofs are re-validated when their target changes | Algorithmic — checkRegression on every RFC affecting target |
| FV-003 | A regressed critical property blocks the offending change | Constitutional — Security Council enforcement |
| FV-004 | Every verification run produces evidence (Law 4) | Architectural — run result logged to EVS |
| FV-005 | Property registry is the single source of truth for proven status | Algorithmic — all status reads from registry |
| FV-006 | Proof methods are reproducible — same target + same tool = same result | Algorithmic — tool versions pinned per artifact |
| FV-007 | Unproven properties are flagged, never assumed secure | Architectural — status defaults to unproven |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Verification owns proof; Pentest owns empirical test; Kernel owns runtime enforcement |
| R2 — Dependency Order | Depends on Security Kernel, CCA, IDS, EVS; no cycles |
| R3 — DRY | Properties defined once in registry; runs reference, not duplicate |
| R4 — Builder Pattern | Verification runs use builder for method and target selection |
| R9 — Deterministic | Same target + same tool version = same proof result |
| R10 — Simpler Over Complex | Static analysis for quick checks; model checking/theorem proving for critical properties |
| R13 — Design for Failure | Regression and proof failure block changes; unproven defaults to insecure |
| R14 — Paved Path | Static analysis on every change; formal proof for critical properties |
| R15 — Open/Closed | New proof methods register via Verification Engine extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/000-Overview.md | Security Council — owns verification program |
| Bible/04-Execution/Security/Hardening/000-Overview.md | Hardening — verified properties confirm baseline controls |
| Bible/04-Execution/Security/Pentest/000-Overview.md | Pentest — empirical validation complements formal proof |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | EAS — non-bypassability property proven here |
| Bible/04-Execution/Security/IDS/001-Registry.md | IDS — identity uniqueness property proven here |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA — capability integrity property proven here |
| Bible/06-Services/ACF/000-Overview.md | ACF — confidentiality property proven here |
| Bible/06-Services/Cryptography/000-CSP.md | Crypto — cryptographic primitives underpin proofs |
| Bible/05-Platform/004-EVS.md | EVS — evidence for all verification runs |
| Bible/08-Interfaces/Console/000-Overview.md | Console — critical regressions escalate here |
| Physics/008-Security.md | Security invariants — properties formalized from these |
| Physics/005-Events.md | Evidence invariants — runs are logged |
