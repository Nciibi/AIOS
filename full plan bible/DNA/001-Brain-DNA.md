# AIOS DNA
## 001 — Brain Architectural Invariants

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | DNA |
| Document ID | DNA-001 |
| Source Laws | Law 9 — Law of Constitutional Supremacy, Law 5 — Law of Identity |
| Source Physics | Physics/011-Design-DNA.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document defines the architectural invariants of the Brain — the cognitive subsystem of AIOS. These invariants are constitutional in nature: they cannot be violated by any implementation, upgrade, or override except through constitutional amendment.

The Brain contains Sou (the single executive intelligence) and all cognitive services. Everything outside the Brain is infrastructure.

## Sou Invariants (SOU-001–007)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-001 | Sou is the only constitutional intelligence in AIOS. Every strategic decision originates from Sou. | All strategic decisions are logged and attributed to Sou. Non-Sou strategic decisions are violations. |
| SOU-002 | Workers cannot independently create missions. Missions are created by Sou and executed by workers. | Mission creation API verifies caller is Sou. Worker-created missions are rejected. |
| SOU-003 | Organizations cannot override Sou's decisions. Organizations execute within bounds set by Sou. | Organization governance is constrained to execution. Strategic override attempts are blocked. |
| SOU-004 | Sou owns the global context. Context System manages it; Sou always has access. | Context System has no access controls restricting Sou. Context eviction requires Sou consent. |
| SOU-005 | Sou owns the final response to the user. Every user-facing output passes through Sou for approval. | No component outside Sou can emit user-facing output. ACF enforces this routing. |
| SOU-006 | The Brain is the only subsystem that contains intelligence. Academy, Security Council, Institutions, Runtime contain no strategic intelligence. | Architectural — documented in Bible structure. Cross-boundary intelligence detection is monitored. |
| SOU-007 | All cognitive services live inside the Brain. No cognitive service exists outside the Brain. | System architecture enforces Brain boundary. External cognitive services are rejected. |

## Brain Invariants (BRAIN-001–009)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural — documented in Bible directory structure. |
| BRAIN-002 | Sou is the only component with strategic decision authority. | Constitutional — SOU-001. Verified by Security Council. |
| BRAIN-003 | The Brain communicates with external systems only through ACF. No direct calls out of the Brain. | Architectural — no system calls from Brain components to external APIs bypassing ACF. |
| BRAIN-004 | No component outside the Brain can create missions. | Constitutional — SOU-002. Mission OS verifies caller identity. |
| BRAIN-005 | Every user-facing response passes through Sou. | Constitutional — SOU-005. ACF routing enforced. |
| BRAIN-006 | The Context System owns the global context window. Single authority for context. | Architectural — no other component may persist or modify global context. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural — service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional — Sou's omniscience within Brain. Access control enforced by Memory OS. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural — all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |

## Brain Service Catalog

| Service | Document | Function | Invariant Coverage |
|---------|----------|----------|-------------------|
| Sou | Brain/Sou/000-Overview.md | Executive intelligence — identity, goals, decisions, delegation | SOU-001–007 |
| Cognitive OS | Brain/Cognitive/000-Overview.md | Reasoning, reflection, metacognition | BRAIN-001, BRAIN-007 |
| Conversation OS | Brain/Conversation/000-Overview.md | Dialogue management, multi-turn context | BRAIN-001, BRAIN-007 |
| Memory OS | Brain/Memory/000-Overview.md | Persistent memory, working memory, retrieval | BRAIN-001, BRAIN-007, BRAIN-008 |
| LLMOS | Brain/LLMOS/000-Overview.md | AI inference pipeline (model routing, prompt compilation, streaming) | BRAIN-001, BRAIN-009 |
| Context System | Brain/Context/000-Overview.md | Global context window management, priority, compression | BRAIN-001, BRAIN-006 |
| Planning System | Brain/Planning/000-Overview.md | Strategic + tactical planning, goal decomposition | BRAIN-001, BRAIN-007 |
| Decision System | Brain/Decision/000-Overview.md | Multi-factor decision making, trade-off analysis | BRAIN-001, BRAIN-007 |
| Tool System | Brain/Tools/000-Overview.md | Tool registry, capability discovery, tool call management | BRAIN-001, BRAIN-007 |
| Attention System | Brain/Attention/000-Overview.md | Priority and focus management | BRAIN-001, BRAIN-007 |
| Personality System | Brain/Personality/000-Overview.md | Identity, values, behavior patterns, communication style | BRAIN-001, BRAIN-007 |
| Voice System | Brain/Voice/000-Overview.md | Speech-to-text, text-to-speech | BRAIN-001, BRAIN-007 |
| Vision System | Brain/Vision/000-Overview.md | Image/video input processing | BRAIN-001, BRAIN-007 |
| Autonomy System | Brain/Autonomy/000-Overview.md | Autonomy levels L0-L4, progression, escalation, override | BRAIN-001, BRAIN-007 |

## Invariant Relationship Map

```
SOU-001 ─┬─ SOU-002 (workers cannot create missions)
          ├─ SOU-003 (orgs cannot override Sou)
          ├─ SOU-004 (Sou owns global context) ── BRAIN-006 (Context System manages)
          ├─ SOU-005 (Sou owns final response)
          ├─ SOU-006 (Brain contains all intelligence)
          └─ SOU-007 (cognitive services inside Brain)

BRAIN-001 ─┬─ BRAIN-002 (Sou has strategic authority) ── SOU-001
            ├─ BRAIN-003 (Brain communicates via ACF only)
            ├─ BRAIN-004 (no external mission creation) ── SOU-002
            ├─ BRAIN-005 (responses pass through Sou) ── SOU-005
            ├─ BRAIN-006 (Context System owns global context) ── SOU-004
            ├─ BRAIN-007 (services are stateless) ── Memory OS
            ├─ BRAIN-008 (Sou has all memory access)
            └─ BRAIN-009 (LLMOS is only inference path)
```

## Cross-Cutting Concerns

### Security

Brain invariants are enforced by the Security Council through the verification pipeline. Violations of SOU-001–007 or BRAIN-001–009 are constitutional violations that trigger immediate suspension of the violating component.

### Evidence

Every Brain invariant check produces an Event. Invariant violations are recorded immutably. The complete invariant compliance history of every Brain component is auditable.

### Lifecycle

Brain services follow the canonical LMS lifecycle. Service initialization includes invariant self-check. Services that cannot satisfy their invariant coverage at startup enter Blocked state.

### Capability Bounds

Brain services operate within capability bounds defined by their Genome (AGS). No Brain service may exceed its constitutional bounds. Capability bound expansion requires RFC approval.

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/02-Core/Brain/000-Overview.md | Brain architecture — cognitive subsystem overview |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou — the executive intelligence |
| Bible/02-Core/Brain/LLMOS/000-Overview.md | LLMOS — inference pipeline (BRAIN-009) |
| Bible/02-Core/Brain/Context/000-Overview.md | Context System (BRAIN-006) |
| Bible/02-Core/Brain/Memory/000-Overview.md | Memory OS (BRAIN-007, BRAIN-008) |
| Bible/0010-Brain-Restructuring-Plan.md | Brain restructuring plan — origin of these invariants |
| DNA/000-AIOS-DNA.md | Design DNA — R1–R15 foundational rules |
| DNA/002-Entity-DNA.md | Entity lifecycle genetics |
| Physics/011-Design-DNA.md | Design DNA normative specification |
| Bible/04-Execution/Security/000-Overview.md | Security Council — invariant enforcement authority |
