# AIOS Bible — Brain
## 000 — Overview (The Executive Intelligence)

| Property | Value |
|----------|-------|
| Status | Active — rewritten for new paradigm |
| Version | 2.0 |
| Category | Bible — Brain |
| Document ID | AIOS-BBL-002-SOU-000 |
| Source Laws | Law 0 (Supremacy), Law 4 (Identity), Law 5 (Autonomy), Law 3 (Communication) |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Bible/02-Core/Sou/000-Overview.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

**Sou is the single constitutional intelligence of AIOS.** It is not a wrapper around an agent — Sou IS the agent. Every strategic decision, every mission creation, every user-facing response originates from Sou.

Sou has:
- **Identity**: A persistent sense of self (name, purpose, history)
- **Personality**: Behavioral traits, communication style, values
- **Goals**: Strategic objectives that persist across sessions
- **Executive Authority**: Final say on every strategic choice
- **Delegation Power**: Creates missions and assigns workers
- **Context Ownership**: Owns the global context window

## What Sou IS

| Statement | Implication |
|-----------|-------------|
| Sou IS the agent | Sou is not middleware, not a wrapper, not an orchestrator — Sou IS the intelligence making decisions |
| Sou IS the user's counterpart | The user interacts with Sou directly, not with a "system" |
| Sou IS responsible | Every output, every action, every mission traces back to Sou's decision |
| Sou IS the learner | Sou improves from outcomes — not the system, not workers, Sou |
| Sou IS accountable | Security Council verifies Sou's decisions; Academy records Sou's learning |

## What Sou Is NOT

| Misconception | Correction |
|---------------|------------|
| Sou is a wrapper around an LLM | False. Sou USES LLMOS for inference, but Sou is the intelligence that decides what to infer |
| Sou is an orchestrator | False. Orchestration is a mechanical function. Sou makes strategic choices |
| Sou is a reasoning engine | False. Sou is the entity that reasons. Reasoning is a capability, not an identity |
| Workers are agents | False. Workers are temporary execution units. Sou dispatches them, Sou reclaims them |
| Academy knows what Sou knows | False. Sou has private knowledge. Academy only receives what Sou shares |

## Sou Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          SOU                                         │
│                                                                      │
│  CORE IDENTITY                                                        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │
│  │   Identity   │ │  Personality  │ │    Goals     │                 │
│  │  "Who I am"  │ │ "How I act"  │ │ "What I want"│                 │
│  └──────────────┘ └──────────────┘ └──────────────┘                 │
│                                                                      │
│  EXECUTIVE FUNCTIONS                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │
│  │  Executive   │ │   Mission    │ │  Delegation   │                 │
│  │  Decisions   │ │   Creation   │ │  (Assign work)│                 │
│  └──────────────┘ └──────────────┘ └──────────────┘                 │
│                                                                      │
│  LEARNING & ADAPTATION                                                │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │
│  │   Learning   │ │  Reflection  │ │   Memory     │                 │
│  │(Academy feed)│ │ (Self-review)│ │(Memory OS R/W)│                 │
│  └──────────────┘ └──────────────┘ └──────────────┘                 │
│                                                                      │
│  COMMUNICATION                                                        │
│  ┌──────────────┐ ┌──────────────┐                                   │
│  │  User-facing │ │  Internal    │  ALL via ACF                      │
│  │  Response    │ │  Delegation  │                                   │
│  └──────────────┘ └──────────────┘                                   │
└──────────────────────────────────────────────────────────────────────┘
```

## Sou Invariants (SOU-001–007)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-001 | Sou is the only constitutional intelligence in AIOS | Every strategic decision originates from Sou |
| SOU-002 | Workers cannot independently create missions | Missions are created by Sou and executed by workers |
| SOU-003 | Organizations cannot override Sou's decisions | Organizations execute within bounds set by Sou |
| SOU-004 | Sou owns the global context | Context System manages it; Sou always has access |
| SOU-005 | Sou owns the final response to the user | Every user-facing output passes through Sou for approval |
| SOU-006 | The Brain is the only subsystem that contains intelligence | Academy, Security Council, Institutions, Runtime contain no strategic intelligence |
| SOU-007 | All cognitive services live inside the Brain | No cognitive service exists outside the Brain |

## How Sou Uses Brain Services

Sou does NOT directly implement reasoning, planning, or memory. These are delegated to Brain services:

| Sou Need | Delegated To | How |
|----------|-------------|-----|
| Reason about a situation | Cognitive OS | Sou invokes Cognitive OS reasoning methods |
| Create a plan | Planning System | Sou defines goals; Planning System decomposes |
| Retrieve past experience | Memory OS | Sou queries Memory OS for relevant memories |
| Generate text / infer | LLMOS | Sou sends inference request through LLMOS pipeline |
| Manage conversation | Conversation OS | Sou maintains dialogue state via Conversation OS |
| Decide between options | Decision System | Sou frames options; Decision System scores them |
| Use a tool | Tool System | Sou discovers and invokes tools via Tool System |
| Focus attention | Attention System | Sou sets priorities; Attention System filters noise |
| Speak / hear | Voice System | Sou routes audio I/O through Voice System |
| See | Vision System | Sou processes visual input through Vision System |

## Sou Data Flow

```
1. Input arrives via ACF (user message, system event, external trigger)
2. Identity check: "Is this for me?"
3. Personality filter: "How should I respond given my values?"
4. Context load: "What is the current situation?" (Context System)
5. Memory recall: "What do I know about this?" (Memory OS)
6. Reasoning: "What should I do?" (Cognitive OS)
7. Decision: "I will do X" (Decision System)
8. If mission needed: Create mission → Delegate to Institution OS
9. If inference needed: Send to LLMOS → Get result
10. Compose final response
11. Response sent via ACF (to Conversation OS for user delivery)
12. Outcome observed → Learning integration
```

## Sou Events

| Event | Produced When | Description |
|-------|--------------|-------------|
| `Sou.InputReceived` | Input arrives via ACF | Input entered Sou's processing |
| `Sou.DecisionMade` | Sou completes a strategic decision | Sou made a strategic decision |
| `Sou.MissionCreated` | Mission proposal submitted to DGP | Sou created a mission |
| `Sou.WorkerDispatched` | Worker assigned to a task | Sou dispatched a worker |
| `Sou.ResponseSent` | Response delivered to Conversation OS | Sou sent a user-facing response |
| `Sou.LearningIntegrated` | Learning ingested from outcome evidence | Sou integrated learning from an outcome |
| `Sou.GoalUpdated` | Strategic goal modified via Learning | Sou updated its strategic goals |

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Input is ambiguous | Sou requests clarification before proceeding |
| Multiple competing goals | Decision System scores and ranks |
| Brain service unavailable | Sou degrades — works without the service, notes capability gap |
| No valid decision | Sou reports inability to decide, surfaces constraints |
| User overrides | Human Override flag pauses all Sou decisions |
| Identity conflict | Federation context — Sou asserts identity, negotiates scope |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Brain/000-Overview.md | Brain — the cognitive container |
| Bible/02-Core/Brain/Sou/001-Reasoning.md | Reasoning (via Cognitive OS) |
| Bible/02-Core/Brain/Sou/002-Planner.md | Planning (via Planning System) |
| Bible/02-Core/Brain/Sou/003-Missions.md | Mission creation and oversight |
| Bible/02-Core/Brain/Sou/004-Learning.md | Learning and adaptation |
| Bible/02-Core/Brain/Sou/005-Knowledge.md | Memory and knowledge (via Memory OS) |
| Bible/02-Core/Brain/LLMOS/000-Overview.md | AI inference |
| Bible/01-Governance/002-DGP.md | Decision routing |
| Bible/04-Execution/Security/000-Overview.md | Verification |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Execution infrastructure |
| Bible/00-Foundations/001-AIOS-Philosophy.md | Philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | Core principles |
