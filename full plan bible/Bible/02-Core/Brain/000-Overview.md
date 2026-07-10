# AIOS Bible — Brain
## 000 — Overview (The Cognitive Container)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain |
| Document ID | AIOS-BBL-002-BRN-000 |
| Source Laws | Law 0 — Law of Supremacy, Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Supersedes | Bible/02-Core/Sou/000-Overview.md (partial — Sou now a component of Brain) |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The **Brain** is the complete cognitive subsystem of AIOS. It contains **Sou** (the single constitutional intelligence) and all cognitive services — the infrastructure Sou uses to perceive, reason, plan, decide, reflect, learn, and communicate.

Everything outside the Brain is infrastructure:
- **Academy** manages knowledge; it does not think
- **Security Council** verifies; it does not decide
- **Institutions** (Missions, Organizations, Workers) execute; they do not originate
- **Runtime** runs code; it does not reason
- **Federation** connects instances; it does not deliberate

Only the Brain contains intelligence.

## Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              BRAIN — COGNITIVE SUBSYSTEM                     ║
║                                                                              ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │  SOU (Executive Intelligence)                                          │  ║
║  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐     │  ║
║  │  │Ident │ │Person│ │Goals │ │Exec  │ │Mission│ │Deleg │ │Learn │     │  ║
║  │  │ity   │ │ality │ │      │ │Decis │ │Create │ │ation │ │ing   │     │  ║
║  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘     │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
║                                    │                                         ║
║                                    ▼                                         ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │  BRAIN SERVICES (Cognitive Infrastructure)                             │  ║
║  │                                                                        │  ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │  ║
║  │  │Cognitive │ │Conversat │ │  Memory   │ │  LLMOS   │ │ Context  │    │  ║
║  │  │   OS     │ │  ion OS  │ │   OS      │ │Inference │ │ System   │    │  ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘    │  ║
║  │                                                                        │  ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │  ║
║  │  │ Planning │ │ Decision │ │   Tool   │ │Attention │ │Personality│    │  ║
║  │  │ System   │ │ System   │ │  System  │ │ System   │ │ System   │    │  ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘    │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  COMMUNICATION: All Brain ↔ external communication flows through ACF         ║
╚══════════════════════════════════════════════════════════════════════════════╝
                    │
                    ▼
   (Infrastructure: Academy · Security Council · Institutions · Runtime · Federation · Domains)
```

## Brain Services

| Service | Document | Status | Description |
|---------|----------|--------|-------------|
| Sou | Brain/Sou/ | Active | Executive intelligence — identity, goals, decisions, delegation |
| Cognitive OS | Brain/Cognitive/ | Active | Reasoning, reflection, metacognition |
| Conversation OS | Brain/Conversation/ | Active | Dialogue management, multi-turn context |
| Memory OS | Brain/Memory/ | Active | Persistent memory, working memory retrieval |
| LLMOS | Brain/LLMOS/ | Active | AI inference pipeline (model routing, prompt compilation, streaming) |
| Context System | Brain/Context/ | Active | Global context window management, priority, compression |
| Planning System | Brain/Planning/ | Active | Strategic + tactical planning, goal decomposition |
| Decision System | Brain/Decision/ | Active | Multi-factor decision making, trade-off analysis |
| Tool System | Brain/Tools/ | Active | Tool registry, capability discovery, tool call management |
| Attention System | Brain/Attention/ | Active | Priority and focus management |
| Personality System | Brain/Personality/ | Active | Identity, values, behavior patterns, communication style |
| Voice System | (planned) | TBD | Speech-to-text, text-to-speech |
| Vision System | (planned) | TBD | Image/video input processing |

## Brain Invariants (BRAIN-001–009)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| BRAIN-001 | Every cognitive service is inside the Brain | Architectural — documented in Bible structure |
| BRAIN-002 | Sou is the only component with strategic decision authority | Constitutional — SOU-001 |
| BRAIN-003 | The Brain communicates with external systems only through ACF | Architectural — no direct calls out of Brain |
| BRAIN-004 | No component outside the Brain can create missions | Constitutional — SOU-002 |
| BRAIN-005 | Every user-facing response passes through Sou | Constitutional — SOU-005 |
| BRAIN-006 | The Context System owns the global context window | Architectural — single authority for context |
| BRAIN-007 | Cognitive services are stateless — all state lives in Memory OS | Architectural — services are reusable pipelines |
| BRAIN-008 | Sou has read access to ALL memories; services have scoped access | Constitutional — Sou's omniscience within Brain |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain | Architectural — no direct provider calls |

## Data Flow

```
User Input
    │
    ▼
┌─────────────────────────────────────────────┐
│  Sou via ACF (authenticated by Security      │
│  Council, logged to Event Store)             │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  Sou — Receives & Processes Input           │
│  ├── Identify self + check personality      │
│  ├── Reason about input (Cognitive OS)      │
│  ├── Plan response (Planning System)        │
│  ├── Consult memory (Memory OS)             │
│  ├── Decide action (Decision System)        │
│  ├── Create mission (delegate to Institution OS)  │
│  ├── Delegate to worker via Institution OS   │
│  └── Compose final response                  │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  LLMOS (if AI inference needed)              │
│  ├── Stage 0-3: Gateway (security, rate)     │
│  ├── Stage 4-11: Pre-processing (routing,   │
│  │   prompt compile, memory inject, etc.)    │
│  ├── Stage 12-17: Execution + Post-processing│
│  └── Return inference result                │
└─────────────────────────────────────────────┘
    │
    ▼
User Response (via Sou → ACF → Conversation OS)
```

## Relationship to Non-Brain Components

| Component | Relationship |
|-----------|-------------|
| Academy | Sou learns from Academy evidence. Academy is a data source, not an intelligence. |
| Security Council | Verifies every action proposed by Sou. Independent arbiter; no strategic authority. |
| Institution OS (Missions, Orgs, Workers) | Executes work packages created by Sou. No autonomous decision authority. |
| Runtime | Executes code delegated by Sou. No reasoning capability. |
| Federation | Connects multiple AIOS instances. Each instance has its own Brain. Federated Brains coordinate via protocols. |
| Domains | Domain-specific knowledge libraries. Consumed by Sou for context, no autonomy. |

## Brain Events

| Event | Description |
|-------|-------------|
| `Brain.ServiceInitialized` | A Brain service completed startup |
| `Brain.ServiceFailed` | A Brain service failed to initialize |
| `Brain.ExternalRequest` | External request entered Brain via ACF |
| `Brain.ResponseReady` | Brain produced a response for the user |
| `Brain.AuthorizationRequired` | Brain action requires Security Council verification |

## Forward References

Brain service specifications have been created across three phases:

- **Phase B** (Context System, Planning System, Decision System, Tool System) — see `Brain/Context/`, `Brain/Planning/`, `Brain/Decision/`, and `Brain/Tools/`.
- **Phase C** (Cognitive OS, Conversation OS, Memory OS, Attention System, Personality System) — see `Brain/Cognitive/`, `Brain/Conversation/`, `Brain/Memory/`, `Brain/Attention/`, and `Brain/Personality/`.
- **Phase D** (Voice System, Vision System) — planned for future specification.

**Sou's sub-files** (`Sou/001-Reasoning.md` through `005-Knowledge.md`) contain the detailed technical content from the old Sou engine, adapted for the new paradigm. They serve as the detailed specification for how Sou interacts with each Brain service.

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/0010-Brain-Restructuring-Plan.md | Plan document for this restructuring |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou — the executive intelligence |
| Bible/02-Core/Brain/LLMOS/000-Overview.md | LLMOS — AI inference pipeline (moved from Bible/04-Execution/) |
| Bible/02-Core/Brain/Context/000-Overview.md | Context System — global context window management |
| Bible/02-Core/Brain/Decision/000-Overview.md | Decision System — multi-factor scoring and trade-off analysis |
| Bible/02-Core/Brain/Planning/000-Overview.md | Planning System — goal decomposition and milestone tracking |
| Bible/02-Core/Brain/Tools/000-Overview.md | Tool System — tool registry, discovery, and invocation |
| Bible/02-Core/Academy/000-Overview.md | Academy — learning infrastructure (outside Brain) |
| Bible/04-Execution/Security/000-Overview.md | Security Council — verification infrastructure |
| Bible/03-Institutions/000-Overview.md | Institutions — execution infrastructure |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime — code execution infrastructure |
| APIs/AIOS-Architecture-Diagram.md | Architecture diagram |
| APIs/000-Master-API-Spec.md | API registry |
