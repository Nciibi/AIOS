# AIOS Bible — Brain Restructuring Plan

> **Purpose:** Define the new "Brain" subsystem — a cognitive container that houses Sou (the single executive intelligence) and all cognitive services. This plan restructures the top of the AIOS architecture based on the insight that Sou is not a wrapper around an agent but IS the agent, and every other component is infrastructure that extends Sou's ability to perceive, decide, organize, and execute.
> **Source:** `sou new idea.md` (ChatGPT conversation 7/10/2026)
> **Status:** Phase A complete — directory created, Brain overview written, Sou rewritten, LLMOS moved, cross-references updated

---

## 1. Core Insight

**Sou is the only constitutional intelligence in AIOS.**

Everything else is infrastructure:
- **Missions** are work packages Sou creates
- **Workers** are temporary execution units Sou dispatches
- **Organizations** are structural containers Sou uses to organize work
- **LLMOS** is the inference pipeline Sou uses to think
- **Memory OS** is where Sou stores what it learns
- **Conversation OS** is how Sou manages dialogue with users
- **Runtime** is the execution layer Sou delegates to

This gives AIOS a clear chain of command:
```
User ←→ Sou (Executive Intelligence)
              │
              ▼
         Mission Creation
              │
              ▼
         Worker Dispatch
              │
              ▼
         Execution (via Runtime + LLMOS)
              │
              ▼
         Results → Sou evaluates → Responds to User
```

---

## 2. The Brain — New Top-Level Subsystem

The **Brain** is the complete cognitive subsystem of AIOS. It contains Sou and all the services Sou needs to perceive, reason, plan, decide, reflect, learn, and communicate.

```
AIOS
│
├── BRAIN                    ← NEW: Cognitive container
│     ├── Sou                ← The executive intelligence itself
│     ├── Cognitive OS       ← Reasoning, reflection, metacognition
│     ├── Conversation OS    ← Dialogue management, multi-turn context
│     ├── Memory OS          ← Persistent memory, working memory
│     ├── Context System     ← Global context window management
│     ├── Planning System    ← Strategic and tactical planning
│     ├── Decision System    ← Multi-factor decision making
│     ├── LLMOS              ← AI inference pipeline (already built)
│     ├── Tool System        ← Tool registry, capability discovery
│     ├── Voice System       ← Speech I/O
│     ├── Vision System      ← Image/video processing
│     ├── Attention System   ← Priority and focus management
│     └── Personality System ← Identity, values, behavior patterns
│
├── Academy                  ← Learning from evidence, knowledge management
├── Security Council          ← Identity, authorization, audit, verification
├── Institution OS            ← Organizations, workers, missions (execution only)
│     ├── Organization OS
│     ├── Worker OS
│     └── Mission OS
├── Runtime                  ← Execution providers
├── Federation               ← Cross-instance protocols
└── Domains                  ← Application domains
```

### What moves under the Brain

| Current Location | Component | New Home |
|-----------------|-----------|----------|
| Bible/02-Core/Sou/ | Sou engine modules | Bible/02-Core/Brain/Sou/ |
| (planned) | Cognitive OS | Bible/02-Core/Brain/Cognitive/ |
| (planned) | Conversation OS | Bible/02-Core/Brain/Conversation/ |
| (planned) | Memory OS | Bible/02-Core/Brain/Memory/ |
| Bible/04-Execution/LLMOS/ | LLMOS | Bible/02-Core/Brain/LLMOS/ |
| (new) | Context System | Bible/02-Core/Brain/Context/ |
| (new) | Planning System | Bible/02-Core/Brain/Planning/ |
| (new) | Decision System | Bible/02-Core/Brain/Decision/ |
| (new) | Tool System | Bible/02-Core/Brain/Tools/ |
| (new) | Voice System | Bible/02-Core/Brain/Voice/ |
| (new) | Vision System | Bible/02-Core/Brain/Vision/ |
| (new) | Attention System | Bible/02-Core/Brain/Attention/ |
| (new) | Personality System | Bible/02-Core/Brain/Personality/ |

### What stays in its current location

| Component | Location | Reason |
|-----------|----------|--------|
| Academy | Bible/02-Core/Academy/ | Learning is not execution; Academy is independent |
| Security Council | Bible/04-Execution/Security/ | Verifies ALL actions, not just brain actions |
| Organizations | Bible/03-Institutions/Organizations/ | Execution infrastructure, not cognition |
| Workers | Bible/03-Institutions/Workers/ | Temporary execution units, not agents |
| Missions | Bible/03-Institutions/Missions/ | Work packages created by Sou but executed externally |
| Runtime | Bible/04-Execution/Runtime/ | Execution layer, not cognitive |
| Federation | Bible/06-Services/Federation/ | Cross-instance protocols, orthogonal to Brain |
| ACF | Bible/06-Services/ACF/ | Universal communication fabric |

---

## 3. Sou — Redefined as Executive Intelligence

### Old model

```
Sou
├── Reasoning
├── Planner
├── Missions
├── Learning
└── Knowledge
```

Sou was treated as an "engine" that aggregated capabilities.

### New model

```
Sou
├── Identity            ← Who Sou is
├── Personality         ← How Sou behaves (values, style, preferences)
├── Goals               ← What Sou wants to achieve
├── Executive Decisions ← Final decision authority
├── Mission Creation    ← Ability to define work packages
├── Delegation          ← Assigning work to organizations/workers
├── Communication       ← User-facing dialogue (uses Conversation OS)
└── Learning            ← Integrating new knowledge (uses Academy)
```

Sou is now the **consciousness** of AIOS. It has:
- **Identity**: A persistent sense of self (name, purpose, history)
- **Personality**: Behavioral traits, communication style, values
- **Memory**: Access to all memory types via Memory OS
- **Goals**: Strategic objectives that persist across sessions
- **Decision Authority**: Final say on every strategic choice
- **Delegation Power**: Creates missions and assigns workers
- **Context Ownership**: Owns the global context window

Sou does NOT directly implement:
- Token-by-token LLM inference (uses LLMOS)
- Vector search for memories (uses Memory OS)
- Conversation state management (uses Conversation OS)
- Multi-turn context threading (uses Conversation OS)
- Image processing (uses Vision System)
- Audio processing (uses Voice System)

These are infrastructure services inside the Brain that Sou orchestrates.

---

## 4. Constitution — New Laws

The current 10 Laws remain unchanged. The following NEW invariants are added to Law 0 (Supremacy) or as a new section in the Constitution:

```
SOU-001: Sou is the only constitutional intelligence in AIOS.
         Every strategic decision originates from Sou.

SOU-002: Workers cannot independently create missions.
         Missions are created by Sou and executed by workers.

SOU-003: Organizations cannot override Sou's decisions.
         Organizations execute within bounds set by Sou.

SOU-004: Sou owns the global context.
         The global context window is managed by the Context System
         within the Brain and is always accessible to Sou.

SOU-005: Sou owns the final response to the user.
         Every user-facing output passes through Sou for approval.

SOU-006: The Brain is the only subsystem that contains intelligence.
         Academy, Security Council, Institutions, Runtime,
         Federation, and Domains contain no strategic intelligence —
         they are infrastructure, not agents.

SOU-007: All cognitive services live inside the Brain.
         No cognitive service (conversation, memory, reasoning,
         planning, reflection, decision) exists outside the Brain.
```

---

## 5. Impact on Existing Architecture

### What does NOT change
- ✅ All 14 LLMOS files just written
- ✅ Security Council 7-stage pipeline
- ✅ Academy knowledge management
- ✅ Organization system
- ✅ Worker system
- ✅ Mission system
- ✅ ACF communication fabric
- ✅ Runtime execution providers
- ✅ Federation protocols
- ✅ Domain definitions
- ✅ Constitutional laws (10 Laws remain)
- ✅ Design DNA (R1-R15)

### What changes (minimal)

| Change | Effort | Description |
|--------|--------|-------------|
| Rename | Low | `Bible/02-Core/Sou/` → `Bible/02-Core/Brain/Sou/` |
| Rewrite | Medium | Sou specification from "engine" to "executive intelligence" |
| Move | Low | LLMOS moves from `Bible/04-Execution/LLMOS/` to `Bible/02-Core/Brain/LLMOS/` |
| Move | Low | Memory OS moves from planned OS location to `Bible/02-Core/Brain/Memory/` |
| Move | Low | Conversation OS moves from planned OS location to `Bible/02-Core/Brain/Conversation/` |
| Create | High | New Brain overview + 6 new subsystems (Context, Planning, Decision, Tools, Voice, Vision, Attention, Personality) |
| Update | Medium | Architecture diagram: new Brain layer at top |
| Update | Medium | Master API Spec: new Brain section + reclassify LLMOS/Memory/Conversation under Brain |

### What must be CREATED new

| New Component | Priority | Description |
|---------------|----------|-------------|
| Brain Overview | P0 | The Brain as a subsystem — architecture, invariants, relationship to Sou |
| Sou Redefinition | P0 | Sou as executive intelligence — identity, personality, goals, executive decisions |
| Context System | P0 | Global context window — what Sou sees, priority management, context compression |
| Decision System | P1 | Structured decision making — multi-factor scoring, trade-off analysis |
| Planning System | P1 | Strategic + tactical planning — goal decomposition, milestone tracking |
| Tool System | P1 | Tool registry, capability discovery, tool call management |
| Attention System | P2 | Priority and focus — what Sou pays attention to, when |
| Personality System | P2 | Identity, values, behavior patterns, communication style |
| Voice System | P3 | Speech-to-text, text-to-speech interfaces |
| Vision System | P3 | Image/video input processing |

---

## 6. Implementation Phases

### Phase A: Restructure (P0 — immediate) ✅ COMPLETE
1. ✅ Create `Bible/02-Core/Brain/` directory structure
2. ✅ Create `Bible/02-Core/Brain/000-Overview.md` — Brain architecture, invariants, subsystem layout
3. ✅ Rewrite Sou: `Bible/02-Core/Brain/Sou/000-Overview.md` as executive intelligence
4. ✅ Move LLMOS: `Bible/02-Core/Brain/LLMOS/` (update cross-references)
5. ✅ Update Architecture Diagram to show Brain as top layer
6. ✅ Update Master API Spec to reflect Brain hierarchy

### Phase B: Core Systems (P0 — next)
1. Create `Bible/02-Core/Brain/Context/000-Overview.md` — Context System
2. Create `Bible/02-Core/Brain/Decision/000-Overview.md` — Decision System
3. Create `Bible/02-Core/Brain/Planning/000-Overview.md` — Planning System
4. Create `Bible/02-Core/Brain/Tools/000-Overview.md` — Tool System

### Phase C: Advanced Systems (P1)
1. Create `Bible/02-Core/Brain/Attention/000-Overview.md` — Attention System
2. Create `Bible/02-Core/Brain/Personality/000-Overview.md` — Personality System
3. Refine Cognitive OS integration
4. Refine Conversation OS integration
5. Refine Memory OS integration

### Phase D: Sensory Systems (P2)
1. Create `Bible/02-Core/Brain/Voice/000-Overview.md` — Voice System
2. Create `Bible/02-Core/Brain/Vision/000-Overview.md` — Vision System

---

## 7. Architecture Diagram (New Top)

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                   BRAIN — COGNITIVE SUBSYSTEM                                      ║
║                                                                                                     ║
║  ┌────────────────────────────────────────────────────────────────────────────────────────────┐     ║
║  │  SOU (Executive Intelligence)                                                               │     ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐             │     ║
║  │  │ Identity │ │Personality│ │  Goals   │ │Executive │ │ Mission  │ │Delegation│             │     ║
║  │  │          │ │          │ │          │ │ Decision │ │ Creation │ │          │             │     ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘             │     ║
║  └────────────────────────────────────────────────────────────────────────────────────────────┘     ║
║                                         │                                                           ║
║                                         ▼                                                           ║
║  ┌────────────────────────────────────────────────────────────────────────────────────────────┐     ║
║  │  BRAIN SERVICES (Sou's cognitive infrastructure)                                           │     ║
║  │                                                                                             │     ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐             │     ║
║  │  │Cognitive │ │Conversat │ │  Memory  │ │  LLMOS   │ │ Context  │ │ Planning │             │     ║
║  │  │   OS     │ │  ion OS  │ │   OS     │ │Inference │ │ System   │ │ System   │             │     ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘             │     ║
║  │                                                                                             │     ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐             │     ║
║  │  │ Decision │ │   Tool   │ │ Attention│ │  Voice   │ │  Vision  │ │Personality│             │     ║
║  │  │ System   │ │  System  │ │ System   │ │  System  │ │  System  │ │ System   │             │     ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘             │     ║
║  └────────────────────────────────────────────────────────────────────────────────────────────┘     ║
║                                                                                                     ║
║  INVARIANTS: Sou is the only constitutional intelligence · All cognitive services are in Brain      ║
║  Sou owns global context · Sou owns final response · Sou creates all missions                       ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝
                                    │
                                    ▼
              (Mission OS → Organization OS → Worker OS → Runtime)
```

---

## 8. Critical Invariants

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

---

## 9. Open Questions

1. **Sou's identity persistence**: How does Sou maintain a sense of self across sessions? Is identity stored in Memory OS or a separate identity store?
2. **Sou in Federation**: When two AIOS instances federate, do both Brains interact? Is there a "super-Sou" for federated contexts?
3. **Sou's learning loop**: How does Sou integrate what it learns from Academy (evidence-based learning) with its personality and goals?
4. **Attention granularity**: Should the Attention System be a separate subsystem or a property of the Context System?
5. **Worker autonomy level**: If workers are "not agents", what degree of autonomy do they have? Can they make tactical decisions within a mission scope?
6. **Migration path**: Should we move the existing Sou files or rewrite them entirely given the paradigm shift?
7. **Brain startup sequence**: What order do Brain services initialize? Does Sou come up first and then start services, or do services start first and then Sou?
8. **Emergency override**: Can Academy or Security Council override a Sou decision (e.g., if Sou goes rogue)?

---

## 10. Related Documents

| Document | Relationship |
|----------|-------------|
| `sou new idea.md` | Original insight — Sou is the only intelligence, Brain is the container |
| `Bible/02-Core/Brain/Sou/000-Overview.md` | New Sou specification (rewritten as executive intelligence) |
| `Bible/02-Core/Brain/LLMOS/000-Overview.md` | LLMOS specification (moved to Brain) |
| `APIs/AIOS-Architecture-Diagram.md` | Architecture diagram (to be updated with Brain) |
| `APIs/000-Master-API-Spec.md` | API registry (to be updated with Brain section) |
| `Bible/0000-Master-Architecture-Plan.md` | Master architecture plan (to reference Brain) |
