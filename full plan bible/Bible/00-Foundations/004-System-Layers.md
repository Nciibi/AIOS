# AIOS Bible — Foundations
## 004 — System Layers

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-004 |
| Source Laws | Law 0 — Law of Layering |
| Source Physics | Physics/011-Design-DNA.md R2 — Dependency Ordering |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## The 5-Layer Stack

AIOS is organised into 5 layers. Each layer depends only on the layers below it. No layer depends on a layer above.

```
┌─────────────────────────────────────┐
│        5. Runtime                   │
│  Execution Engines (Claude, Codex,   │
│  Ollama, Browser, Trading, Robotics) │
├─────────────────────────────────────┤
│        4. Implementation             │
│  Code (Rust/Go/TypeScript)          │
│  Deployed Services                   │
├─────────────────────────────────────┤
│        3. Bible                      │
│  Specifications                     │
│  (Foundations, Governance, Core,    │
│   Institutions, Execution, Platform, │
│   Services, Domains, Interfaces,    │
│   Reference, Research)              │
├─────────────────────────────────────┤
│        2. Physics                    │
│  Invariants, Mechanisms             │
│  (Identity, Sessions, Events,       │
│   Lifecycles, Capabilities,         │
│   Security, Interaction, Execution, │
│   Design DNA, Experience)           │
├─────────────────────────────────────┤
│        1. Law                       │
│  Constitution of AIOS               │
│  (10 Laws, immutable)              │
└─────────────────────────────────────┘
```

## Layer Descriptions

### 1. Constitution (Layer 1)

The Constitution defines the Laws of AIOS. These are immutable — they can only be amended through the constitutional RFC process. Every layer below must be consistent with the Constitution.

**Contents**: Physics/000-Laws.md (10 laws: Identity, Capability Bounds, Non-Execution, Lifecycle Compliance, etc.)

**Creators**: Constitutional RFC process only

### 2. Physics (Layer 2)

Physics defines the invariants, mechanisms, and natural laws of the AIOS universe. Each Physics document specifies 10 invariants that every implementation must satisfy. Physics documents are the normative specification — they are what an implementation must conform to.

**Key Documents**: Sessions, Events, Lifecycles, Capabilities, Security, Interaction, Execution, Design DNA, Experience

**Relationship to Bible**: Physics defines *what* (10 invariants per document). Bible defines *how* (detailed specifications in each volume).

### 3. Bible (Layer 3)

The Bible is the detailed specification of AIOS. It organises specifications into 11 volumes (Foundations, Governance, Core, Institutions, Execution, Platform, Services, Domains, Interfaces, Reference, Research). Every Bible document implements one or more Physics invariants.

**Key Documents**: 0000-Master-Architecture-Plan plus ~200 specification files

**Enforcement**: Bible documents are normative. Implementation must match Bible specifications.

### 4. Implementation (Layer 4)

Implementation is the code that realises the Bible specifications. This layer includes all services, engines, libraries, and tools that make up the running AIOS system. Each component in Implementation must trace to one or more Bible documents.

**Languages**: Rust (primary), Go, TypeScript

**Enforcement**: Tests verify conformity to Bible specifications. Code review checks Design DNA compliance.

### 5. Runtime (Layer 5)

Runtime is the execution environment — the providers (Claude, Codex, Ollama, Browser, Trading, Robotics) that actually execute the actions authorised by the verification pipeline. Runtime is the thinest layer; it simply executes what the layers below have authorised.

**Key Components**: Runtime SDK, execution providers, sandboxing

**Enforcement**: Runtime validates execution tokens against the Security Council's signature before executing.

## Layer Boundaries

### No Reverse Dependencies

A layer may never depend on a layer above it. This means:
- Implementation never references Runtime directly
- Bible never configures Implementation
- Physics never references specific Bible documents (though Bible references Physics invariants)

### Cross-Layer Communication

Communication between layers follows defined patterns:
- **Downward requests**: Requests flow down (e.g., Bible asks Physics "what invariants apply?")
- **Upward notifications**: Events flow up (e.g., Implementation produces Events that Bible specifies)
- **Horizontal messaging**: Same-layer entities communicate through ACF

### Layer Violations

Common layer violations and their remedies:

| Violation | Example | Remedy |
|----------|---------|--------|
| Bible referencing Implementation | "The Rust struct for Identity is..." | Replace with specification, not implementation reference |
| Implementation depending on upper layer | A service importing a Runtime provider | Inject Runtime provider through DI (R6) |
| Physics referencing Bible | "The IRS implementation should..." | Remove. Physics is invariant, not implementation |
| Layer skipping | Implementation reading the Constitution directly | Route through Bible specification first |