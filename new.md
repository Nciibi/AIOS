# new.md — AIOS / Souu Project Notes

> Source: `ChatGPT-souuSouu Agent System Design.md` (74,817 lines, 200+ turn ChatGPT export)
> Purpose: Capture the project design + documentation style so we can write the
> Constitution / Bible sections well. This is a working notebook, not a spec.

---

## 1. One-line identity

> "ECC is the army. Souu is the general who commands the army."

- **AIOS** = an AI Operating System (conceptually a Linux distro layer) that orchestrates autonomous intelligence.
- **Souu / Sou** = the *commander brain*. Strategic only. **Never executes.**
- **ECC** = the agent harness (skills, hooks, agents for Claude Code / Codex / OpenCode / Cursor / Gemini). Used as the execution compatibility layer, not the orchestrator.

---

## 2. The core mental model (why it exists)

Traditional orchestrators think: `User → Agent → Answer`.
AIOS thinks:

```
User
 ↓
Understand the goal
 ↓
Plan
 ↓
Choose best models
 ↓
Choose best agents (workers)
 ↓
Create more agents if needed
 ↓
Supervise
 ↓
Test
 ↓
Merge results
 ↓
Learn from everything
 ↓
Answer
```

Key principle repeated throughout: **think in capabilities/workers, never in "Claude" or "Codex".**
The runtime is just the engine that powers a worker. An `Agent` is NOT a model.

```rust
Agent {
    id: UUID,
    name: "Backend Worker",
    runtime: ClaudeCode,   // engine, not identity
    model: "claude-opus-4.8",
    provider: Anthropic,
    role: Backend,
    skills: [...],
    permissions: [...],
    memory: ...,
    supervisor: ...,
    workspace: ...,
    status: Running,
}
```

---

## 3. Layered architecture (evolved version from the chat)

```
USER
 ↓
Interaction
 ↓
Sou  ──┬──→ Academy (collective intelligence)
       └──→ Organization System (OSYS)
                 ↓
              Directors → Managers → Supervisors → Workers
                 ↓
            Runtime Manager (Claude/Codex/OpenCode/OpenClaw/Hermes/Ollama)
                 ↓
            AIOS Kernel / Linux
```

Documented layers (from the design):
- **Layer 5 — Agent Factory**: dynamically spawns/destroys workers on demand ("like Kubernetes / Docker containers").
- **Layer 6 — Runtime Manager**: launches each runtime as an independent session (own provider, model, API key, temperature, workspace).
- **Layer 7 — Scheduler**: Linux-process-scheduler analog for AI. Priority → Resources → Spawn → Monitor → Scale → Destroy. Autoscaling.
- **Layer 8 — Resource Manager**: knows RAM/CPU/GPU/API credits/latency/bandwidth/tokens/battery. Routes work to local vs cloud.
- **Layer 9 — Model Router**: picks the model per task. No user intervention unless override.
- **Layer 11 — Knowledge Graph**: permanent, shared, evolving learning (the Academy).

---

## 4. Subsystems → Constitution mapping

| Design term | Constitution doc | Notes |
|---|---|---|
| Sou (commander, reasons/plans) | Article III `002-Sou` | Strategic only; separation of reasoning/execution is constitutional. |
| Academy / Knowledge Graph | `003-Academy` | Permanent collective intelligence; verification required. |
| Organization System (OSYS) | `004-OSYS` | **Key evolution:** Sou decides *what* orgs are needed; OSYS creates/manages/scales/dissolves/governs them. Keeps Sou strategic. |
| Digital Twin System (DTS) | `005-DTS` | Predictive mirror of platform state. |
| Resource Operating System (ROS) | `006-ROS` | Resource scheduling + Model Router live here. |
| Security Kernel | `007-Security-Kernel` | Zero trust, deterministic authz. |
| Shared Infrastructure (ACF/IRS/AOM) | `008-Shared-Infrastructure` | ACF = comms bus; IRS = identity/registry; AOM = object model. |
| Workers / Agent sessions | `011-Workers` | Runtime-agnostic, disposable, each own model/provider/workspace. |
| Organizations + Governance | `009` / `010` | Permanent orgs; Director→Manager→Supervisor→Worker. |
| Cooperation / Collective Intelligence | `013` / `015` | All comms via ACF; shared learning. |
| Runtime Neutrality | `014` | No runtime privileged; capabilities route. |
| Autonomy | `016` | Workers autonomous within authority; human supreme. |

Already-encoded in `CONSTITUTION/Appendix/Definitions.md`: DTS, OSYS, ROS.
Already-referenced in `References.md`: "OSYS Bible", "ROS Bible", "DTS Bible" → the **Bible** (technical architecture) level is still unwritten.

---

## 5. The OSYS split (most important architectural refinement)

> "Sou decides **what** organizations are needed. OSYS is responsible for creating,
> managing, scaling, dissolving, and governing organizations throughout their lifecycle."
> — design chat, ~line 24008

This is exactly why Article III was split into **Part A (Institutions)** and **Part B (Society)**:
Sou stays strategic; OSYS becomes the "organizational operating system."
Keep this separation sacred when writing the sections.

---

## 6. Worker / Agent session model

- Workers are **infinite & disposable**: `Build Firefox → 1 Architect, 20 Backend, 10 UI, 8 QA, 5 Docs, 3 Security, 2 Perf, 1 Supervisor = 50 sessions`.
- Each session independently chooses: provider, model, temperature, max tokens, permissions, budget.
- Same runtime, different config = different worker (e.g., `Claude Backend #1` Opus vs `Claude UI` Fable vs `Claude QA` Sonnet).
- Workers own: workspace, memory, context, runtime, model, logs, IPC. Nothing shared unless desired.
- Lifecycle: Created → Initialized → Running → Blocked/Paused → Completed → Destroyed.

---

## 7. Example workers (use as concrete scenarios in docs)

- **Shannon** — network/security worker using `nmap` + `wireshark`. The canonical "user wants to scan the network → Sou chooses Shannon" example.
- **Backend / UI / QA / Crypto / Supervisor / Architect** — software engineering division.
- Workers can be supervised: each subagent has a role, a supervisor, and a tester; same agent type can run different models.

---

## 8. Communication rule

> "Never allow agents to talk directly."

All communication through the **Communication Bus (ACF)**. Benefits called out: logging, replay, debugging, security, permissions. Maps directly to DNA Principle 18 (Layer Independence) + ACF as "nervous system."

---

## 9. Learning loop (continuous improvement)

```
Task Completed → Performance Analysis → Extract Successful Patterns
 → Store in Knowledge Graph → Improve Future Strategies → Update Routing & Recommendations
```

This is the *Experience* asset. Verification is mandatory before anything enters the Academy.
Over time the whole ecosystem gets better at planning/routing/execution without hard-coding.

---

## 10. Implementation direction

- **Rust-first**: `sou-core` in Rust for performance + memory safety. Modules: scheduler, planner, knowledge, memory, ipc, skills, models, security, plugins, runtime, metrics, telemetry, cli, daemon.
- ECC becomes the execution compatibility layer under AIOS; Souu becomes the independent orchestration daemon.
- Roadmap from the chat: (1) keep ECC skills/hooks; (2) build Souu in Rust; (3) plugin/runtime abstraction; (4) knowledge graph + learning; (5) deep Linux desktop/kernel integration.

---

## 11. Documentation style to copy (how we should document)

Extracted from the strongest responses in the source — apply to every Constitution/Bible section:

1. **Numbered progressive sections** — one idea per `# N.` block.
2. **ASCII diagrams everywhere** — trees, pipelines, layered stacks. Legibility over prose.
3. **"Instead of X → do Y"** — contrast naive vs better approach.
4. **Concrete scenarios** — real prompts ("Build a secure messaging app", "My WiFi is slow") with the system's actual response.
5. **Plain-language analogies** — the "explain like I'm 4" mayor-vs-toy-box section proves complex architecture is explainable. Required by DNA Principle 14 (Explainability).
6. **"If I were building today" roadmap** — turn vision into ordered actionable steps.
7. **Back every claim with a concrete choice** (Rust, specific models, specific tools).
8. **Every doc ends with:** `Related Documents`, `Rationale`, `Future Extensions` (confirmed as a hard convention in the chat backlog, ~line 24053).

---

## 12. Conventions / backlog already agreed in the chat

- Document tiers: **DNA → Constitution → Physics → Bible → Implementation** (matches `013-Evolution.md` pyramid).
- Every document must end with: Related Documents, Rationale, Future Extensions.
- Backlog items still TODO: AIOS Design Language (ADL), AIOS Patterns, AIOS Object Model (AOM) Spec, ACF Complete Spec, Architecture Decision Records.
- Integration order: finish DNA + Constitution + Physics + Bible **before** adding backlog systems, "so we don't destabilize the architecture."

---

## 13. Open questions / gaps for the Bible level

- **OSYS / ROS / DTS Bible** specs referenced but not yet written (this is the missing "Bible" tier).
- `AOM` (AI Object Model) and `AOP` (AI Object Protocol?) acronyms still undefined — pin down.
- Exact `sou-core` module boundaries vs the Constitution's "Engine" taxonomy need reconciling.
- How Worker lifecycle states in the design (Created/Initialized/Running/Blocked/Paused/Completed/Destroyed) map to the Constitution lifecycle (Creation/Activation/Operation/Suspension/Termination/Archival) — align terminology.

---

## 14. Quick reference — vocabulary alignment

| Chat word | Constitution / DNA word |
|---|---|
| Souu | Sou |
| Agent / Worker session | Worker |
| Agent Factory | Worker lifecycle (under OSYS) |
| Model Router | Capability routing (ROS) |
| Resource Scheduler | Resource Manager (ROS) |
| Knowledge Graph | Academy (Knowledge + Experience) |
| Skills | Skill (intelligence asset) |
| Communication Bus | ACF |
| ECC | Runtime execution compatibility layer |
| Organization System | OSYS |
| Runtime (Claude/Codex/...) | Runtime (implementation of a Capability) |
