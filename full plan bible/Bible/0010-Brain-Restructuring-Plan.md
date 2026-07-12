# AIOS Bible — Brain Restructuring Plan

> **Purpose:** Define the new "Brain" subsystem — a cognitive container that houses Sou (the single executive intelligence) and all cognitive services. This plan restructures the top of the AIOS architecture based on the insight that Sou is not a wrapper around an agent but IS the agent, and every other component is infrastructure that extends Sou's ability to perceive, decide, organize, and execute.
> **Source:** `sou new idea.md` (ChatGPT conversation 7/10/2026)
> **Status:** Phase A + B + C + D + Phase 1 complete — all 14 Brain services specified (Sou, LLMOS, Context, Decision, Planning, Tools, Attention, Personality, Cognitive OS, Conversation OS, Memory OS, Voice, Vision, Autonomy), all cross-references fixed, Master API Spec updated, CCA docs + AOP docs created

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
│     ├── Personality System ← Identity, values, behavior patterns
│     └── Autonomy System    ← L0-L4 autonomy, progression, escalation
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
| (new) | Autonomy System | Bible/02-Core/Brain/Autonomy/ |

### What stays in its current location

| Component | Location | Reason |
|-----------|----------|--------|
| Academy | Bible/02-Core/Academy/000-Overview.md | Learning is not execution; Academy is independent |
| Security Council | Bible/04-Execution/Security/000-Overview.md | Verifies ALL actions, not just brain actions |
| Organizations | Bible/03-Institutions/Organizations/ | Execution infrastructure, not cognition |
| Workers | Bible/03-Institutions/Workers/ | Temporary execution units, not agents |
| Missions | Bible/03-Institutions/Missions/ | Work packages created by Sou but executed externally |
| Runtime | Bible/04-Execution/Runtime/000-Overview.md | Execution layer, not cognitive |
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
| Autonomy System | P0 | L0-L4 autonomy levels, AMS/ACE/ABE engines, escalation chain |

---

## 6. Implementation Phases

### Phase A: Restructure (P0 — immediate) ✅ COMPLETE
1. ✅ Create `Bible/02-Core/Brain/` directory structure
2. ✅ Create `Bible/02-Core/Brain/000-Overview.md` — Brain architecture, invariants, subsystem layout
3. ✅ Rewrite Sou: `Bible/02-Core/Brain/Sou/000-Overview.md` as executive intelligence
4. ✅ Move LLMOS: `Bible/02-Core/Brain/LLMOS/` (update cross-references)
5. ✅ Update Architecture Diagram to show Brain as top layer
6. ✅ Update Master API Spec to reflect Brain hierarchy

### Phase B: Core Systems (P0) ✅ COMPLETE
1. ✅ Created `Bible/02-Core/Brain/Context/000-Overview.md` — Context System (window management, priority, compression, TTL, registry)
2. ✅ Created `Bible/02-Core/Brain/Decision/000-Overview.md` — Decision System (scoring, trade-offs, constraints, criteria registry)
3. ✅ Created `Bible/02-Core/Brain/Planning/000-Overview.md` — Planning System (goal decomposition, milestones, dependencies, progress tracking)
4. ✅ Created `Bible/02-Core/Brain/Tools/000-Overview.md` — Tool System (registry, discovery, invocation, validation)
5. ✅ Updated Brain overview services table (Context, Planning, Decision, Tools → Active)
6. ✅ Updated Forward References to reflect Phase B completion

### Phase C: Advanced Systems (P1) ✅ COMPLETE
1. ✅ Created `Bible/02-Core/Brain/Attention/000-Overview.md` — Attention System
2. ✅ Created `Bible/02-Core/Brain/Personality/000-Overview.md` — Personality System
3. ✅ Created `Bible/02-Core/Brain/Cognitive/000-Overview.md` — Cognitive OS
4. ✅ Created `Bible/02-Core/Brain/Conversation/000-Overview.md` — Conversation OS
5. ✅ Created `Bible/02-Core/Brain/Memory/000-Overview.md` — Memory OS (previously empty placeholder)
6. ✅ Updated Brain overview services table (5 services → Active)
7. ✅ Updated Forward References to reflect Phase C completion

### Phase D: Sensory Systems (P2) ✅ COMPLETE
1. ✅ Created `Bible/02-Core/Brain/Voice/000-Overview.md` — Voice System (STT/TTS, voice profiles, streaming)
2. ✅ Created `Bible/02-Core/Brain/Vision/000-Overview.md` — Vision System (image analysis, OCR, scene description, video processing, document parsing)
3. ✅ Updated Brain overview services table (2 services → Active)
4. ✅ Updated Forward References to reflect Phase D completion
5. ✅ Added 3.14 Voice + 3.15 Vision to Master API Spec

### Phase 1: Post-Restructuring — Accepted Features (P0) ✅ COMPLETE
1. ✅ Created `Bible/05-Platform/Observability/000-AOP.md` — AOP (AIOS Observability Platform)
2. ✅ Created `Bible/02-Core/Brain/Autonomy/000-Overview.md` — Autonomy System (AMS/ACE/ABE)
3. ✅ Created `Bible/04-Execution/Security/CCA/000-CCA.md` — CCA (Capability Certification Authority)
4. ✅ Created `Bible/04-Execution/Security/CCA/001-CAS.md` — CAS (Capability Assignment System)
5. ✅ Created `Bible/04-Execution/Security/CCA/002-CDG.md` — CDG (Capability Dependency Graph)
6. ✅ Updated Brain overview services table (Autonomy → Active)
7. ✅ Updated cross-references: CCA path in Execution-Auth/EAS, ROS/RMP

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
| `Bible/02-Core/Brain/Context/000-Overview.md` | Context System — global context window management |
| `Bible/02-Core/Brain/Decision/000-Overview.md` | Decision System — multi-factor scoring |
| `Bible/02-Core/Brain/Planning/000-Overview.md` | Planning System — goal decomposition |
| `Bible/02-Core/Brain/Tools/000-Overview.md` | Tool System — tool registry and invocation |
| `Bible/02-Core/Brain/Attention/000-Overview.md` | Attention System — priority and focus |
| `Bible/02-Core/Brain/Personality/000-Overview.md` | Personality System — identity and values |
| `Bible/02-Core/Brain/Cognitive/000-Overview.md` | Cognitive OS — reasoning and reflection |
| `Bible/02-Core/Brain/Conversation/000-Overview.md` | Conversation OS — dialogue management |
| `Bible/02-Core/Brain/Memory/000-Overview.md` | Memory OS — persistent storage backbone |
| `APIs/AIOS-Architecture-Diagram.md` | Architecture diagram (updated with Brain layer) |
| `APIs/000-Master-API-Spec.md` | API registry (updated with Brain section 3.1–3.13) |
| `Bible/0000-Master-Architecture-Plan.md` | Master architecture plan |

---

## 11. Phase A Fix Log (post-completion audit)

| # | Issue | File(s) | Fix |
|---|-------|---------|-----|
| 1 | Brain data flow box had two `└──` lines (should be `├──` then `└──`) | `Brain/000-Overview.md:115-117` | Corrected box-drawing characters |
| 2 | Old `Sou/000-Overview.md` lacked deprecation notice | `Bible/02-Core/Sou/000-Overview.md` | Added `DEPRECATED` banner, updated `Superseded By` |
| 3 | `LLMOS/005-Memory-Injection.md` referenced `Bible/03-OS/Memory` (never-built path) | `005-Memory-Injection.md:19,157` | Updated to `Bible/02-Core/Brain/Memory/` |
| 4 | 12 LLMOS files retained `Execution/LLMOS` headers, old Doc IDs (`AIOS-BBL-004-*`) | `001`–`013` (excl. `000`, `005`) | Headers → `Brain/LLMOS`, IDs → `AIOS-BBL-002-*` |
| 5 | Architecture Diagram LAYER 5 missing box-top `┌───┐` line | `AIOS-Architecture-Diagram.md:118` | Added box-top border |
| 6 | API Spec Security Council Section 4 was empty (no subsections) | `000-Master-API-Spec.md` | Added 10 subsections (4.1–4.10) with 106 catalog entries, full renumbering to 514 items |
| 7 | Phase B review: missing type definitions | `Decision/000-Overview.md`, `Planning/000-Overview.md`, `Tools/000-Overview.md` | Added `RankedOption`, `ViolatedConstraint` (Decision); `ResourceEstimate` (Planning); `ReturnSchema`, inline types for `rate_limits`, `cost`, `error`, `resource_usage`, `status` (Tools) |
| 8 | Phase B review: Context System missing cross-reference | `Context/000-Overview.md` | Added `Brain/Tools/` to Related Documents |
| 9 | Phase B review: Brain overview missing Phase B entries | `Brain/000-Overview.md` | Added 4 Phase B services to Related Documents |
| 10 | Physics/003-Communication.md doesn't exist (referenced by 3 files) | `Context/000-Overview.md`, `Tools/000-Overview.md`, `LLMOS/000-Overview.md` | Changed to Physics/009-Interaction.md (correct file for Law 3) |
| 11 | 6 undefined types in Context data model | `Context/000-Overview.md` | Added inline definitions for InputMessage, WorkingMemory, ConversationTurn, MissionState, SystemSignal, CompressedWindow, ContextItem |
| 12 | DecisionContext undefined in Decision/Planning | `Decision/000-Overview.md` | Added DecisionContext type definition |
| 13 | ExecutionGraph undefined in Planning | `Planning/000-Overview.md` | Added ExecutionGraph + ExecutionNode type definitions |
| 14 | Tools cross-references used relative paths | `Tools/000-Overview.md` | Changed to absolute paths (Bible/04-Execution/...) |
| 15 | Planning ROS cross-reference wrong path | `Planning/000-Overview.md` | Changed from Bible/05-Platform/ROS/ to Bible/02-Core/ROS/000-Overview.md |
| 16 | Master API Spec missing Phase B service entries | `000-Master-API-Spec.md` | Added 3.5 Context, 3.6 Decision, 3.7 Planning, 3.8 Tool — 68 new catalog entries, renumbered to 582 |
| 17 | Architecture Diagram LAYER 5 box alignment | `AIOS-Architecture-Diagram.md` | Fixed indentation: all box lines (┌, │, └) now start at column 2 |
| 18 | Brain overview Source Laws format inconsistent | `Brain/000-Overview.md` | Changed parenthetical format to em-dash format |
| 19 | Brain/Memory/ directory didn't exist | Filesystem | Created empty placeholder directory |
| 20 | Context TTL table naming mismatch | `Context/000-Overview.md` | "Conversation turn" → "Conversation history" |
| 21 | Brain overview services table showed Phase C services as TBD | `Brain/000-Overview.md` | Changed 5 services (Cognitive, Conversation, Memory, Attention, Personality) from TBD→Active |
| 22 | Brain overview Forward References said Phase C services "planned or in development" | `Brain/000-Overview.md` | Rewritten to describe Phases B/C/D as completed stages |
| 23 | Brain overview Related Documents missing Phase C services | `Brain/000-Overview.md` | Added 5 Phase C service entries to Related Documents |
| 24 | Master API Spec Security Council+ sections (4–10) had overlapping numbers with Phase C entries (302–391) | `000-Master-API-Spec.md` | Renumbered sections 4–10 by +90 (302–582 → 392–672); clean sequence 100–672 |
| 25 | Sou/001-Reasoning.md used relative paths for DGP reference | `Sou/001-Reasoning.md` | `Governance/002-DGP.md` → `Bible/01-Governance/002-DGP.md` (2 occurrences) |
| 26 | Sou/004-Learning.md used relative path for Academy KMS | `Sou/004-Learning.md` | `Core/002-KMS.md` → `Bible/02-Core/Academy/002-KMS.md` |
| 27 | Plan document Related Documents stale — still said "to be updated" | `0010-Brain-Restructuring-Plan.md` | Updated all 12 Brain service refs and completed status markers |
| 28 | Plan document status line only mentioned Phase A+B | `0010-Brain-Restructuring-Plan.md` | Updated to "Phase A + B + C complete — all 12 Brain services specified" |
| 29 | Plan document Phase C section unmarked | `0010-Brain-Restructuring-Plan.md` | Added ✅ markers to all 7 Phase C items, added "PENDING" to Phase D |
