# AIOS Bible — Governance
## 000 — Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Governance |
| Document ID | AIOS-BBL-001-000 |
| Source Laws | Law 0 — Law of Constitutional Supremacy, Law 4 — Law of Evidence |
| Source Physics | Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Governance defines how AIOS governs itself — how the Constitution is maintained, how decisions are made, how changes are proposed and approved, and how knowledge of the Constitution is managed. Governance is the mechanism by which AIOS ensures its own constitutional compliance over time.

## Structure

Governance contains 7 documents:

| # | Document | Content | Reading Order |
|---|----------|---------|---------------|
| 000 | Overview (this file) | Governance architecture, relationship to other volumes | 1 |
| 001 | CLS — Constitutional Lifecycle Service | Constitution versioning, amendment, enforcement | 2 |
| 002 | DGP — Decision Gateway Process | How constitutional decisions flow from Sou to implementation | 3 |
| 003 | CRP — Change Request Pipeline | RFC lifecycle: submission → review → approval → implementation | 4 |
| 004 | CKR — Constitutional Knowledge Repository | Searchable, queryable constitution | 5 |
| 005 | ADG — Architectural Decision Gateway | Governance for architecture decisions | 6 |
| 006 | AKM — Autonomous Knowledge Management | Academy governance for knowledge lifecycle | 7 |

## Governance Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Governance Architecture                       │
│  ┌────────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   CLS      │  │   DGP    │  │   CRP    │  │   ADG    │   │
│  │(Constitutn)│─►│ (Decisn  │─►│ (Change  │─►│ (Arch    │   │
│  │ Lifecycle  │  │  Gateway)│  │ Request  │  │ Decision)│   │
│  └────────────┘  └──────────┘  └──────────┘  └──────────┘   │
│       │                                                       │
│       ▼                                                       │
│  ┌────────────┐  ┌──────────┐                                 │
│  │   CKR      │  │   AKM    │                                 │
│  │(Knowledge  │  │(Autonom. │                                 │
│  │ Repository)│  │ Knowledge│                                 │
│  └────────────┘  └──────────┘                                 │
└──────────────────────────────────────────────────────────────┘
```

## Relationship to Other Volumes

| Volume | Relationship |
|--------|-------------|
| Foundations | Governance implements PHI-001 (Constitutional AI), CPR-009 (Constitutional Supremacy), CPR-002 (Law-Driven Design) |
| Core (Sou) | Sou proposes decisions; DGP routes them through the governance process |
| Core (Academy) | AKM governs Academy knowledge; CKR stores constitutional knowledge |
| Security Council | CRP changes require Security Council approval; CLS enforcement relies on Security Council |
| Institutions | Organizations participate in governance through DGP; Missions operate within governance constraints |

## Invariants

1. **Constitutional Grounding**: Every governance process is derived from the Constitution. No governance process may contradict a Constitutional Law.
2. **Amendability**: The Constitution may be amended only through the CLS process (RFC with Security Council + Sou approval). No other process may modify the Constitution.
3. **Evidence-Captured**: Every governance decision produces at least one Event. Decisions without evidence are not valid.
4. **Deterministic Process**: Given the same inputs, governance processes always produce the same outputs. Process steps are defined, not discretionary.
5. **Separation of Powers**: The entity that proposes a change (CRP) is separate from the entity that approves it (Security Council) and the entity that implements it (Implementation teams). No entity may perform more than one role in the same governance process.