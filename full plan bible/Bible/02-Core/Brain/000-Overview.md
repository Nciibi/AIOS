# AIOS Bible â€” Brain
## 000 â€” Overview (The Cognitive Container)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain |
| Document ID | AIOS-BBL-002-BRN-000 |
| Source Laws | Law 9 â€” Law of Constitutional Supremacy, Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/000-Laws.md |
| Supersedes | Bible/02-Core/Sou/000-Overview.md (partial â€” Sou now a component of Brain) |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The **Brain** is the complete cognitive subsystem of AIOS. It contains **Sou** (the single constitutional intelligence) and all cognitive services â€” the infrastructure Sou uses to perceive, reason, plan, decide, reflect, learn, and communicate.

Everything outside the Brain is infrastructure:
- **Academy** manages knowledge; it does not think
- **Security Council** verifies; it does not decide
- **Institutions** (Missions, Organizations, Workers) execute; they do not originate
- **Runtime** runs code; it does not reason
- **Federation** connects instances; it does not deliberate

Only the Brain contains intelligence.

## Architecture

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                              BRAIN â€” COGNITIVE SUBSYSTEM                     â•‘
â•‘                                                                              â•‘
â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â•‘
â•‘  â”‚  SOU (Executive Intelligence)                                          â”‚  â•‘
â•‘  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”     â”‚  â•‘
â•‘  â”‚  â”‚Ident â”‚ â”‚Personâ”‚ â”‚Goals â”‚ â”‚Exec  â”‚ â”‚Missionâ”‚ â”‚Deleg â”‚ â”‚Learn â”‚     â”‚  â•‘
â•‘  â”‚  â”‚ity   â”‚ â”‚ality â”‚ â”‚      â”‚ â”‚Decis â”‚ â”‚Create â”‚ â”‚ation â”‚ â”‚ing   â”‚     â”‚  â•‘
â•‘  â”‚  â””â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜     â”‚  â•‘
â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â•‘
â•‘                                    â”‚                                         â•‘
â•‘                                    â–¼                                         â•‘
â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â•‘
â•‘  â”‚  BRAIN SERVICES (Cognitive Infrastructure)                             â”‚  â•‘
â•‘  â”‚                                                                        â”‚  â•‘
â•‘  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”‚  â•‘
â•‘  â”‚  â”‚Cognitive â”‚ â”‚Conversat â”‚ â”‚  Memory   â”‚ â”‚  LLMOS   â”‚ â”‚ Context  â”‚    â”‚  â•‘
â•‘  â”‚  â”‚   OS     â”‚ â”‚  ion OS  â”‚ â”‚   OS      â”‚ â”‚Inference â”‚ â”‚ System   â”‚    â”‚  â•‘
â•‘  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â”‚  â•‘
â•‘  â”‚                                                                        â”‚  â•‘
â•‘  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”‚  â•‘
â•‘  â”‚  â”‚ Planning â”‚ â”‚ Decision â”‚ â”‚   Tool   â”‚ â”‚Attention â”‚ â”‚Personalityâ”‚    â”‚  â•‘
â•‘  â”‚  â”‚ System   â”‚ â”‚ System   â”‚ â”‚  System  â”‚ â”‚ System   â”‚ â”‚ System   â”‚    â”‚  â•‘
â•‘  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â”‚  â•‘
â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â•‘
â•‘                                                                              â•‘
â•‘  COMMUNICATION: All Brain â†” external communication flows through ACF         â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
                    â”‚
                    â–¼
   (Infrastructure: Academy Â· Security Council Â· Institutions Â· Runtime Â· Federation Â· Domains)
```

## Brain Services

| Service | Document | Status | Description |
|---------|----------|--------|-------------|
| Sou | Brain/Sou/ | Active | Executive intelligence â€” identity, goals, decisions, delegation |
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
| Voice System | Brain/Voice/ | Active | Speech-to-text, text-to-speech |
| Vision System | Brain/Vision/ | Active | Image/video input processing |
| Autonomy System | Brain/Autonomy/ | Active | Autonomy levels L0-L4, progression, escalation, override |

## Brain Invariants (BRAIN-001â€“009)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| BRAIN-001 | Every cognitive service is inside the Brain | Architectural â€” documented in Bible structure |
| BRAIN-002 | Sou is the only component with strategic decision authority | Constitutional â€” SOU-001 |
| BRAIN-003 | The Brain communicates with external systems only through ACF | Architectural â€” no direct calls out of Brain |
| BRAIN-004 | No component outside the Brain can create missions | Constitutional â€” SOU-002 |
| BRAIN-005 | Every user-facing response passes through Sou | Constitutional â€” SOU-005 |
| BRAIN-006 | The Context System owns the global context window | Architectural â€” single authority for context |
| BRAIN-007 | Cognitive services are stateless â€” all state lives in Memory OS | Architectural â€” services are reusable pipelines |
| BRAIN-008 | Sou has read access to ALL memories; services have scoped access | Constitutional â€” Sou's omniscience within Brain |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain | Architectural â€” no direct provider calls |

## Data Flow

```
User Input
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Conversation OS (entry point for all        â”‚
â”‚  user interactions, regardless of modality)  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Attention System (filter signals,           â”‚
â”‚  manage focus, route to Sou)                â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Sou via ACF (authenticated by Security      â”‚
â”‚  Council, logged to Event Store)             â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Sou â€” Receives & Processes Input           â”‚
â”‚  â”œâ”€â”€ Identify self + check personality      â”‚
â”‚  â”œâ”€â”€ Consult context (Context System)       â”‚
â”‚  â”œâ”€â”€ Reason about input (Cognitive OS)      â”‚
â”‚  â”œâ”€â”€ Plan response (Planning System)        â”‚
â”‚  â”œâ”€â”€ Consult memory (Memory OS)             â”‚
â”‚  â”œâ”€â”€ Decide action (Decision System)        â”‚
â”‚  â”œâ”€â”€ Invoke tools if needed (Tool System)   â”‚
â”‚  â”œâ”€â”€ Create mission (delegate to Institution OS)  â”‚
â”‚  â”œâ”€â”€ Delegate to worker via Institution OS   â”‚
â”‚  â””â”€â”€ Compose final response                  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  LLMOS (if AI inference needed)              â”‚
â”‚  â”œâ”€â”€ Stage 0-3: Gateway (security, rate)     â”‚
â”‚  â”œâ”€â”€ Stage 4-11: Pre-processing (routing,   â”‚
â”‚  â”‚   prompt compile, memory inject, etc.)    â”‚
â”‚  â”œâ”€â”€ Stage 12-17: Execution + Post-processingâ”‚
â”‚  â””â”€â”€ Return inference result                â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚
    â–¼
User Response (via Sou â†’ Conversation OS â†’ User)
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

| Event | Produced When | Description |
|-------|--------------|-------------|
| `Brain.ServiceInitialized` | After Brain service startup completes | A Brain service completed startup |
| `Brain.ServiceFailed` | Brain service initialization error | A Brain service failed to initialize |
| `Brain.ExternalRequest` | External request received via ACF | External request entered Brain via ACF |
| `Brain.ResponseReady` | Response composed and ready for delivery | Brain produced a response for the user |
| `Brain.AuthorizationRequired` | Action requires Security Council verification before execution | Brain action requires Security Council verification |

## Forward References

Brain service specifications have been created across three phases:

- **Phase B** (Context System, Planning System, Decision System, Tool System) â€” see `Brain/Context/`, `Brain/Planning/`, `Brain/Decision/`, and `Brain/Tools/`.
- **Phase C** (Cognitive OS, Conversation OS, Memory OS, Attention System, Personality System) â€” see `Brain/Cognitive/`, `Brain/Conversation/`, `Brain/Memory/`, `Brain/Attention/`, and `Brain/Personality/`.
- **Phase D** (Voice System, Vision System) â€” see `Brain/Voice/` and `Brain/Vision/`.
- **Phase 1** (Autonomy System) â€” see `Brain/Autonomy/`.

**Sou's sub-files** (`Sou/001-Reasoning.md` through `005-Knowledge.md`) contain the detailed technical content from the old Sou engine, adapted for the new paradigm. They serve as the detailed specification for how Sou interacts with each Brain service.

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/0010-Brain-Restructuring-Plan.md | Plan document for this restructuring |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou â€” the executive intelligence |
| Bible/02-Core/Brain/LLMOS/000-Overview.md | LLMOS â€” AI inference pipeline (moved from Bible/04-Execution/) |
| Bible/02-Core/Brain/Context/000-Overview.md | Context System â€” global context window management |
| Bible/02-Core/Brain/Decision/000-Overview.md | Decision System â€” multi-factor scoring and trade-off analysis |
| Bible/02-Core/Brain/Planning/000-Overview.md | Planning System â€” goal decomposition and milestone tracking |
| Bible/02-Core/Brain/Tools/000-Overview.md | Tool System â€” tool registry, discovery, and invocation |
| Bible/02-Core/Brain/Attention/000-Overview.md | Attention System â€” priority and focus management |
| Bible/02-Core/Brain/Personality/000-Overview.md | Personality System â€” identity, values, behavior patterns |
| Bible/02-Core/Brain/Cognitive/000-Overview.md | Cognitive OS â€” reasoning, reflection, metacognition |
| Bible/02-Core/Brain/Conversation/000-Overview.md | Conversation OS â€” dialogue management, session lifecycle |
| Bible/02-Core/Brain/Memory/000-Overview.md | Memory OS â€” persistent memory, working memory, vector store |
| Bible/02-Core/Brain/Voice/000-Overview.md | Voice System â€” speech-to-text and text-to-speech |
| Bible/02-Core/Brain/Vision/000-Overview.md | Vision System â€” image and video processing |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy System â€” L0-L4 autonomy levels, progression, escalation |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” learning infrastructure (outside Brain) |
| Bible/04-Execution/Security/000-Overview.md | Security Council â€” verification infrastructure |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Institutions â€” execution infrastructure |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime â€” code execution infrastructure |
| DNA/001-Brain-DNA.md | Brain architectural invariants â€” SOU-001-007, BRAIN-001-009 |
| APIs/AIOS-Architecture-Diagram.md | Architecture diagram |
| APIs/000-Master-API-Spec.md | API registry |
