# AIOS Research
## 000 — Phase 2: Autonomous Orchestration

| Property | Value |
|----------|-------|
| Status | Draft |
| Version | 0.1 |
| Category | Research |
| Document ID | RESEARCH-000 |
| Source Laws | Law 2 — Law of Non-Execution, Law 5 — Law of Identity |
| Source Physics | Physics/011-Design-DNA.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Phase 2 extends AIOS from governed single-instance operation into autonomous orchestration. The core question: **How does Sou delegate strategic intent into parallel execution at scale without becoming the bottleneck?**

This document explores the research required to enable Sou to create, monitor, and dissolve dynamic Organizations on demand — spawning fleets of workers across runtimes and models, each with independent sessions, providers, and capability bounds.

## Research Areas

### Area 1: Dynamic Agent Factory

The Agent Factory is the mechanism by which Sou creates workers on demand. Rather than pre-defining every worker type, Sou reasons about the task and instantiates the optimal mix of runtimes, models, and roles.

**Key Questions:**
- How does Sou determine the optimal number of workers for a given mission?
- What is the template language for defining worker genomes at runtime?
- How does the factory handle heterogeneous runtimes (Claude Code, Codex, OpenCode, Ollama, Hermes) under a single mission?
- What is the session lifecycle for factory-created workers? (Created → Planned → Assigned → Running → Completed → Destroyed)

**Design Reference:**

From `ChatGPT-souuSouu Agent System Design.md` (project root):

```
Agent Factory creates unlimited sessions:
  ├── Claude Backend #1 (Opus 4.8, Anthropic)
  ├── Claude Backend #2 (Opus 4.8, Anthropic)
  ├── Claude UI (Fable, Anthropic)
  ├── Codex Security (GPT-5.5, OpenAI)
  ├── Hermes Research (Qwen3 30B, Ollama)
  └── OpenCode Rust (Qwen 30B, Local)
```

Each session is independent — its own provider, model, temperature, max tokens, permissions, and budget. Workers are processes, not agents. They don't decide strategy — they execute missions.

### Area 2: Hierarchical Organization Formation

Currently, Organizations are created manually through OSYS. Phase 2 research explores Sou forming Organizations autonomously in response to mission complexity.

**Proposed Architecture:**

```
Mission Complexity: 9/10
  │
  ▼
Sou creates Organization:
  ├── General (architectural oversight)
  ├── Division A: Backend
  │   ├── Worker: Rust #1
  │   ├── Worker: Rust #2
  │   └── Worker: Database
  ├── Division B: Frontend
  │   ├── Worker: UI
  │   ├── Worker: UX
  │   └── Worker: Accessibility
  └── Division C: QA
      ├── Worker: Tester
      ├── Worker: Security
      └── Worker: Performance
```

**Key Questions:**
- What triggers Sou to create a multi-division Organization vs. a flat worker pool?
- How are division commanders selected? (Workers with higher autonomy levels?)
- How does resource allocation cascade from Organization → Department → Worker?
- What is the teardown protocol when the mission completes?

### Area 3: Autonomous Resource Scheduling

Sou must decide not just *what* to do, but *how* to allocate finite resources across competing missions.

**Decision Matrix:**

| Resource | Constraint | Allocation Strategy |
|----------|-----------|---------------------|
| LLM tokens | Per-provider quota | Mission priority + estimated complexity |
| Worker slots | Max concurrent workers | Parallelism benefit vs. coordination overhead |
| GPU compute | Single GPU (local models) | Queue depth + model size |
| API rate limits | Per-provider limits | Round-robin with backoff |
| Budget | Per-organization cap | Proportional allocation across missions |

**Key Questions:**
- How does Sou estimate resource requirements before creating workers?
- What happens when a high-priority mission arrives and resources are exhausted? (Preemption? Queuing? Escalation to human?)
- How does Sou balance cost vs. speed? (e.g., Claude Opus for critical path, Qwen for routine tasks)

### Area 4: Model Router

Sou must route each subtask to the optimal model based on task characteristics, not just availability.

**Routing Criteria:**

| Task Type | Recommended Model | Fallback | Rationale |
|-----------|-------------------|----------|-----------|
| Architecture design | Claude Opus 4.8 | GPT-5.5 | Highest reasoning depth |
| Frontend UI | Claude Fable | Gemini | Strong design sensibilities |
| Security audit | Codex / GPT-5.5 | Claude Sonnet | Security training data |
| Reverse engineering | Codex | GPT-5.5 | Code analysis strength |
| Simple script | Qwen 30B (local) | Ollama models | Cost-efficient, fast |
| Documentation | Claude Sonnet | Gemini | Balanced quality/speed |
| Research paper | GPT-5.5 | Claude Opus | Broad knowledge coverage |

**Key Questions:**
- How does Sou classify tasks to select the right model?
- What telemetry feeds back into routing decisions? (Speed, quality, cost per task type)
- How does Sou handle model unavailability? (Graceful degradation with capability gap notification)

### Area 5: Mission-to-Result Pipeline

The end-to-end flow from Sou's strategic decision to delivered result, with autonomous orchestration:

```
User Request
  │
  ▼
Sou (Brain)
  ├── Intent Detection (Cognitive OS)
  ├── Task Classification
  ├── Complexity Analysis
  ├── Required Skills Identification
  ├── Resource Estimation
  │
  ▼
Strategy Decision
  ├── Number of workers
  ├── Worker types (runtimes + models)
  ├── Organization structure
  ├── Budget allocation
  └── Timeline estimate
  │
  ▼
Agent Factory creates workers
  │
  ▼
Workers execute in parallel
  │
  ▼
Sou monitors progress (exception-based)
  │
  ▼
Results merge → Sou reviews → Final response
```

## Open Questions

| Q-ID | Question | Priority |
|------|----------|----------|
| OQ-001 | How does Sou determine whether parallelism will improve throughput or add overhead? | P0 |
| OQ-002 | What is the minimum viable worker count for a mission? | P0 |
| OQ-003 | How does Sou handle worker failure mid-mission? (Restart? Replace? Escalate?) | P0 |
| OQ-004 | What autonomy level should factory-created workers have? (L0 directed vs. L1 supervised) | P1 |
| OQ-005 | How are worker outputs merged when workers produce conflicting results? | P1 |
| OQ-006 | Should Sou present its orchestration plan to the user before executing? | P1 |
| OQ-007 | How does the system bill costs back to missions and organizations? | P2 |

## RFCs Needed

| RFC | Title | Description |
|-----|-------|-------------|
| RFC-ORCH-001 | Agent Factory Specification | Worker template instantiation, session lifecycle, runtime binding |
| RFC-ORCH-002 | Dynamic Organization Formation | Criteria for Sou creating multi-division orgs, teardown protocol |
| RFC-ORCH-003 | Model Router Specification | Task classification, model selection criteria, fallback chains |
| RFC-ORCH-004 | Resource Estimation Protocol | Cost/speed prediction before worker creation, budget enforcement |

## Dependencies

| Dependency | Relationship |
|-----------|-------------|
| Bible/02-Core/Brain/Sou/002-Planner.md | Sou's planning engine — this phase adds autonomous planning |
| Bible/02-Core/Brain/Sou/003-Missions.md | Mission creation — this phase adds dynamic mission decomposition |
| Bible/02-Core/OSYS/000-Overview.md | OSYS — Organization lifecycle management (needs dynamic creation API) |
| Bible/02-Core/ROS/000-Overview.md | ROS — Resource allocation (needs predictive estimation) |
| Bible/02-Core/Brain/LLMOS/002-Router.md | LLMOS Router — model selection (needs task-aware routing) |
| Bible/03-Institutions/Workers/000-Overview.md | Workers — session lifecycle (needs factory integration) |
| Bible/02-Core/AGS/000-Overview.md | AGS — Genomes (needs dynamic genome templates) |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime — execution backends (needs factory binding) |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/10-Research/000-Phases-2-5.md | High-level research roadmap — this file deepens Phase 2 |
| Bible/10-Research/001-Autonomy-Evolution.md | Autonomy levels L0–L4 research |
| Bible/0007-Implementation-Roadmap.md | Implementation phasing — Phase 2 schedule |
| Bible/0008-Future-Research.md | Research agenda and open questions |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy System — L0–L4 progression |
| ChatGPT-souuSouu Agent System Design.md (project root) | Original design vision — Agent Factory, Model Router, dynamic orgs |
| sou new idea.md (project root) | Brain/Sou paradigm — Sou as single executive intelligence |
