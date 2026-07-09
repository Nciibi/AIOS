# new.md — AIOS / Souu Complete Project Notebook

> Source: `ChatGPT-souuSouu Agent System Design.md` (74,817 lines, 200+ turn ChatGPT export)
> Scope: ENTIRE conversation read end-to-end (via 7 parallel readers covering lines 1 → 74817).
> Purpose: A working notebook to learn the project "like code" — architecture, design decisions,
> evolution, naming, and the documentation methodology — so we can write the Constitution / Bible well.

---

## 0. TL;DR mental model

> "ECC is the army. Souu is the general who commands the army."
> "Linux virtualized hardware. Docker virtualized applications. Kubernetes virtualized clusters. AIOS virtualizes intelligence."

- **AIOS** = an AI Operating System (conceptually a Linux distro layer) that orchestrates autonomous intelligence.
- **Sou / Souu** = the *Commander Brain* (Strategic Intelligence). Reasons/plans/**never executes**.
- **ECC** (`affaan-m/ECC`) = the existing agent harness (skills/hooks/agents). Becomes the runtime execution compatibility layer, NOT the orchestrator.
- Workers are runtime-agnostic, disposable execution units. The runtime (Claude/Codex/OpenCode/OpenClaw/Hermes/Ollama) is just the engine.

---

## 1. The document tier model (the spine of everything)

```
DNA  →  Constitution  →  Physics  →  Bible  →  RFC  →  Implementation
```
- **DNA** — Immutable identity. "What makes AIOS AIOS?" Never changes. (docs/00-DNA, 000–014)
- **Constitution** — Governance / authority / society. "What is allowed?" Written as *law* (RFC-2119 `SHALL`). Articles I–V + Appendices.
- **Physics** — Universal laws / invariants. "What MUST always be true?" (Mission/Worker/Org lifecycle, capability routing, execution flow.)
- **Bible** — Technical architecture. "How is AIOS built?" Components, protocols, algorithms, data structures, interfaces, SDKs.
- **RFC** — Change proposals. "Nothing enters AIOS without an RFC."
- **Implementation** — Rust code, CLIs, adapters, tests.

**Golden rule of tiers:** Each tier answers exactly one question at its own layer and never duplicates another layer's responsibility.
**Most important discipline (learned the hard way):** the Constitution is *law* — it must NOT leak Bible concepts (engines, SDKs, registries, pipelines). Those live only in the Bible.

Another common framing used in the chat: `Specification (DNA/Constitution/Physics/Bible/RFC) ↓ Runtime ↓ Ecosystem`.

---

## 2. The Constitutional Institutions (Part A — permanent, built into AIOS)

| # | Name | Acronym / Full | Responsibility | Doc ID |
|---|------|----------------|----------------|--------|
| 1 | Sou | Strategic Intelligence | Human intent → safe/observable Missions. Plans, recommends, simulates, estimates. **Never executes.** | CON-III-A-002 |
| 2 | Academy | Collective Intelligence | Permanent verified knowledge, skills, experience, templates, benchmarks, policies. "Constitutional memory." | CON-III-A-003 |
| 3 | OSYS | Organization System | Creates/governs/evolves/retires **Organizations** (the operational society). "Sou decides *what*; OSYS manages." | CON-III-A-004 |
| 4 | DTS | Digital Twin System | Predictive simulation before real execution. "Predicts, never executes." | CON-III-A-005 |
| 5 | ROS | Resource Orchestrator | Governs the resource *economy*: CPU/GPU/RAM/tokens/money/energy/time budgets, quotas, scheduling. | CON-III-A-006 |
| 6 | AGS | AI Genome System | Defines/validates/versions/evolves deterministic blueprints ("Genomes") for every entity. | CON-III-A-007 |
| 7 | Security Kernel | Constitutional Trust Authority | Zero-Trust verification: identity, auth, authorization, policy, audit, **Execution Tokens**. | CON-III-A-008/009 |
| 8 | Shared Infrastructure | ACF, IRS, AOM, AOP | Enable comms/identity/semantics/observability. **Serve everyone, never govern.** | CON-III-A-008 |

### The Four Constitutional Branches
- **Strategic**: Sou, Academy, DTS
- **Operational**: OSYS, Organizations, Workers, Runtimes, Engines, ROS
- **Trust**: Security Kernel
- **Shared Infrastructure**: ACF, IRS, AOM, AOP

### Shared Infrastructure primitives
- **ACF** = AI Communication Fabric — universal messaging (commands/queries/events/streams/pub-sub/notifications/broadcasts). "Nothing bypasses ACF."
- **IRS** = Identity & Registry Service — global AIObject IDs, discovery, ownership, versioning, relationships. (Like `/proc` + K8s API + DNS.)
- **AOM** = AI Object Model — all first-class entities inherit `AIObject`.
- **AOP** = AIOS Observability Platform — metrics, logs, traces, health, dashboards, "black box recorder."
- **LMS** = Lifecycle Management System — shared state-machine framework for all entities.

---

## 3. The Constitutional Society (Part B — Organizations, Workers, Missions)

- **Organization** — permanent operational society specialized in one domain (Coding, Security, Research, FPGA, Trading…). Owns Operational Intelligence. Outlives its Workers.
- **Departments** — permanent functional specialization units inside an Organization (Backend, Frontend, Security…). Bible-level, not Constitution.
- **Governance Hierarchy** — Director → Managers → Supervisors → Workers. **Hierarchy = responsibility, not power.** Four simultaneous graphs: Authority (top-down), Reporting (bottom-up), Collaboration (via ACF), Knowledge (Academy↔Org↔Worker).
- **Workers** — temporary execution entities. `Worker = Genome + Assigned Skills + Mission + Execution Context + Runtime + Policies + Resources + Execution Token`. No permanent memory.
- **Missions** — the constitutional contract between Human Intent and execution. The center of AIOS. Lifecycle: Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived.
- **Lifecycles** — universal state machine for every entity.
- **Cooperation** — distinct from communication (ACF moves messages; cooperation moves *work*).
- **Collective Intelligence** — Academy's permanent verified knowledge (top of the 5-layer intelligence pyramid).
- **Operational Intelligence** — Organization-owned, evolves, NOT permanent like Collective Intelligence.
- **Runtime Neutrality** — constitutional law: no entity depends on a specific model/provider/runtime. Capability-based execution.
- **Autonomy** — 5 levels (L0 Human Controlled → L4 Constitutional Autonomy). Delegated, bounded, explainable. Escalation: Worker → Supervisor → Manager → Director → Sou → Human.
- **Evolution** — evidence-driven, governed, reversible (uses DTS simulation before approval).
- **Federation** — reserved/empty (protocols AIP/RXP/GXP/KXP… reserved for later).

### The 5-layer Intelligence Model (a core original idea)
```
Human Knowledge
  → Collective Intelligence (Academy, permanent)
    → Operational Intelligence (Organization, local)
      → Functional Intelligence (Department)
        → Mission Intelligence (Mission)
          → Execution Context (Worker, temporary)
```

---

## 4. The Execution / Security pipeline (the heart of the system)

Constitutional execution (no stage may be skipped):
```
Intent → Resolver → Context → Capability → Policy → Risk → Execution Plan → Execution → Audit → Forensics
```
Refined security pipeline (Article IV):
```
Identity → Authentication → Authorization → Policy Evaluation →
Capability Verification → Risk Assessment → Execution Authorization →
Execution → Audit → Evidence
```
- **Identity** (who) → **Authentication** (prove) → **Authorization** (may?) → **Policy** (rules) →
  **Capability** (can? "permission ≠ capability") → **Risk** (should now? "authorized+capable ≠ should execute") →
  **Execution Authorization** (non-transferable, non-replayable, temporary **Execution Token**) → Execution.
- **Audit** records history; **Evidence** *proves* history. Both append-only. Evidence feeds Academy → Evolution.
- **Zero Trust**: trust never assumed, continuously earned via verification. Isolation is the default constitutional state.

---

## 5. Engines (reusable OS services, one responsibility each)

Full enumerated set: Planner, Runtime, Scheduler, Knowledge, Memory, Workflow, Mission, Identity, Lifecycle, Learning, Resource, Simulation, Monitoring, Interaction, Skill, Cost, Reputation, Event Bus, Time, Marketplace, Organization, Policy, Capability, Worker Factory, Recovery, Audit, Evidence, Trust, Cryptography, Compliance, Graph…

Engines were later grouped:
- **Core Services** (always on): Planner, Scheduler, Runtime, Memory, Knowledge, Resource, Security, IPC, Monitoring.
- **Intelligence Services**: Model Router, Recommendation, Learning, Knowledge Graph, Context, Decision.
- **Execution Services**: Agent/Worker Factory, Skill Manager, Workspace Manager, Organization Manager, Session Manager, Recovery.

**Key engine definitions:**
- **Agent Factory / Worker Factory** — dynamically clones a Template → injects config/model/skills → launches → destroys when done ("like Docker/Kubernetes containers"). Autoscaling.
- **Runtime Manager / Runtime Engine** — launches each runtime as an independent session (own provider, model, API key, temperature, workspace).
- **Model Router** — auto-selects model per task (Rust→Opus, Frontend→Fable, Refactor/RE→Codex, Docs→Gemini, small→Qwen, Security→Opus). "Never ask the user which model."
- **Resource Engine / ROS** — tracks CPU/RAM/GPU/battery/credits/latency/bandwidth/tokens; routes local vs cloud.
- **Skills Engine** — injects skills into sessions ("like mounting a filesystem", not copying).
- **IPC / ACF** — no direct agent-to-agent comms.

---

## 6. The AIOS Object Model (AOM)

All first-class entities inherit `AIObject` (Rust trait):
```rust
trait AIObject {
    id();          // immutable UUID
    receive();
    send();
    subscribe();
    publish();
}
```
Standard properties: Immutable ID, Version, Owner, CreatedAt, UpdatedAt, Tags, Metadata, Permissions, Lifecycle State, Audit History, Relationships.

Taxonomy categories: Actors, Strategic Objects, Structural Objects, Execution Objects, Intelligence Assets, Communication Objects, Trust Objects, Runtime Objects, System Services, System Resources, Knowledge Objects, Interaction Objects, Infrastructure.
Object lifetimes: **Permanent** (Knowledge, Experience, Skills, Organizations, Templates, Policies) / **Semi-Permanent** (Missions, Workflows, Benchmarks) / **Temporary** (Workers, Sessions, Messages).

---

## 7. Key Design Decisions & their rationale (the "why")

| Decision | Rationale |
|---|---|
| Agents are runtime-agnostic **Workers**, not "Claude/Codex" | Future-proof; vendors come and go, AIOS survives. "Route to capabilities, not models." |
| **Template vs Session** split | Proven cloud pattern (deployment vs container); enables unlimited parallel workers. |
| **Agent Factory** creates/destroys on demand | Resource efficiency + autoscaling like k8s. |
| **Organizations** over independent agents | Structure preserves governance/specialization/experience; workers temporary, orgs permanent. |
| **Sou never executes** (the "first law") | Prevents privilege creep; makes the system verifiable. "Sou is the only conductor; engines are the musicians." |
| **Kernel knows nothing about LLMs** | Everything is a "client" requesting an "intent"; keeps kernel small + reusable. |
| **AIOS sits ABOVE Linux, never replaces it** | Linux = trusted execution substrate (namespaces, seccomp, AppArmor, cgroups); AIOS adds intent/security/knowledge. |
| **Knowledge instead of conversation** | Conversations expire; knowledge compounds → system improves over time. |
| **Capability-based runtimes** | New tools = new adapter; no core redesign. Like Linux's generic GPU interface. |
| **Fail-Closed, Unforgeable Tokens, No Symlink Races, Stateless Verification, Strict Capabilities** | Security mandate. |
| **Genome-driven instantiation** | Every entity originates from a validated, versioned, signed, reproducible Genome ("like DNA/Git"). |
| **Constitution = law, Bible = architecture** | Keeps the Constitution stable/timeless; implementation details belong in the Bible. |
| **One authority per constitutional document** | Prevents overlap between Amendment/Review/Ratification/Versioning/etc. |

**Trade-off priority order:** Security → Architectural Integrity → Long-Term Maintainability → Runtime Independence → Explainability → Extensibility → Performance.

---

## 8. How the design EVOLVED (contradictions to resolve before writing the Bible)

1. **Sou vs OSYS split** — Early diagrams: `Sou → Organizations`. Refined: `Sou → OSYS → Organizations`. Sou decides *what* orgs are needed; OSYS owns the full org lifecycle. **This is the most important refinement** — it validates the Article III Part A/Part B split. The frozen architecture diagrams still need this retrofitted.
2. **"Agents" → "Workers"** — explicit rename. "Agent = AI; Worker = unit of work." Affects ALL prior "agent" language. Must use "Worker" everywhere.
3. **"Layers" → "Planes"** — renamed (planes = independent responsibility domains interacting via defined interfaces, Kubernetes-style). Use "Planes."
4. **Pillar count drift** — 4 → 5 → 6 pillars over time. Final Identity doc (DNA-009) settles on **five permanent pillars**: Sou, Academy, ACF, Security Kernel, Linux. (IRS was called a "sixth pillar" at one point but is Infrastructure, not a pillar.)
5. **Academy grew** — from "vector store / RAG" → first-class "collective intelligence / educational system."
6. **DTS** — "Simulation Engine" → "Digital Twin System" (predictive intelligence: "Should we do this? How? Safest strategy?").
7. **ROS** — "resource manager" → "constitutional economy" (budget + capacity + scheduler + optimization). Added late as the *missing* core subsystem.
8. **AGS** — "Organization Genome" → universal "AI Genome System" (Genomes for Org/Dept/Worker/Mission/Skill/Runtime).
9. **Security Kernel** — "Security Kernel" → "Constitutional Trust Authority" (broader: identity/authz/policy/risk/audit/trust).
10. **Article IV identity correction** — Article IV = *Security* (WHAT security means); Article III's Security Kernel = *WHO enforces*. Distinct.
11. **Trust / Evidence / Audit / Compliance reclassified** — moved OUT of the Security article into **Shared Infrastructure** (reused platform-wide).
12. **Execution Isolation Platform** — relocated from Security → `04-Execution` in the Bible.
13. **Bible structure replaced** — early flat feature folders revoked; replaced by 11-folder layered tree (`00-Foundations`…`10-Research`) "organized by architectural layer, not feature."
14. **Documentation methodology pivot** — early docs became repetitive templates; later switched to RFC/kernel-spec style (BAS + DQC). See §11.
15. **Sou spelling drift** — `souu`/`Souu`/`Sou`/`Soou`/`Souuu` all appear. **Normalize to "Sou"** (single) and "SOUU" (caps in diagrams).

---

## 9. Naming / terminology conventions (enforce these)

**Canonical terms (correct / incorrect):**
- AIOS (not "AI Operating System", "Artificial OS")
- **Sou** (not Master Agent, Chief Agent, Coordinator, Supervisor AI, Manager AI)
- **Academy** (not Knowledge Base, Memory System, Learning Engine, Brain, Database)
- **Organization** (not Team, Department, Squad, Crew, Group) — note: Departments ARE a real sub-concept, but "Team" is forbidden.
- **Worker** (not Agent, Bot, Assistant, Executor)
- **Mission** (not Task, Job, Prompt, Request, Workflow) — "Tasks may exist internally. The user interacts with Missions."
- **Capability** (not Feature, Power, Function, Runtime Ability)
- **Runtime** (not Provider, Model, Engine, Backend)
- **Engine** (not Manager, Service, Module, Daemon)
- **AI Communication Fabric / ACF** (not Message Bus, IPC Layer, Transport Layer)
- **Security Kernel** (not Security Manager, Permission Engine, Security Service)
- **AIObject** (not Entity, Node, Resource, Item)

**Acronyms (expand on first use):** AIOS, ACF, IRS, AOM, AOP, OSYS, DTS, ROS, AGS, LMS, SDK, API, RFC, ADR, ECC. Later: RMP, RXP, AIP, KXP/GXP/MXP/OXP/SXP/EXP/TXP/PXP/CXP/IXP, CLS, DGP, CKR, CIS, CRP, ADG, AKM, RP, BAS, DQC, PSAP, SSM/IDS/ATS/AZS/PS/CAS/RS/EAS/CSP/CAM/EVS/AUS/EPG/EIP/BG/GFW/TP/CP.

**Document ID scheme:** `AIOS-<TIER>-<ARTICLE>-<PART>-<NNN>` e.g. `AIOS-CON-III-A-002`, `AIOS-DNA-010`, `AIOS-CON-V-C-010`.
**Header table on every doc:** `Status | Immutable`, `Version | 1.0`, `Category | Constitution`, `Document ID`, `Applies To`.
**Normative keywords (RFC 2119):** SHALL, SHALL NOT, MUST, MUST NOT, SHOULD, MAY.
**Rust:** Types `PascalCase`, fns `snake_case`, const `SCREAMING_SNAKE_CASE`, traits `PascalCase`, modules `snake_case`.
**REST:** nouns (`/missions`, `/workers`); HTTP method = action. **Events:** past tense (`MissionCreated`). **Commands:** imperative (`CreateMission`). **Queries:** info-only (`FindKnowledge`).
**File naming:** Markdown `Title-Case.md`, Rust `snake_case.rs`, Config `kebab-case.toml`, Dirs `snake_case/`.
**Reserved prefixes:** `Mission*`, `Worker*`, `Organization*`, `Runtime*`, `Engine*`, `Skill*`, `Knowledge*`, `Experience*`, `Policy*`, `Intent*`, `Capability*`.

---

## 10. The Constitution article structure (as built)

- **Preamble**
- **Article I — Human Sovereignty**: Human Authority / Human Rights / Human Responsibilities / Human Override.
- **Article II — AIOS Governance**: AIOS Authority / Constitutional Government / Separation of Powers / Checks and Balances / Constitutional Capabilities / Constitutional Obligations.
- **Article III — Constitutional Institutions and Society**: Part A (Institutions 001–008: Entities/Institutions, Sou, Academy, OSYS, DTS, ROS, AGS, Security Kernel, Shared Infrastructure) + Part B (Society: Organizations, Governance Hierarchy, Departments, Workers, Missions, Lifecycles, Cooperation, Collective Intelligence, Operational Intelligence, Runtime Neutrality, Autonomy, Evolution, Federation).
- **Article IV — Security**: Part A (Principles: Security, Zero Trust, Identity, Authentication, Authorization, Policy Enforcement) + Part B (Operational: Capability Verification, Risk Assessment, Execution Authorization, Secrets & Cryptography, Audit & Evidence, Sandboxing & Isolation) + Part C (Guarantees: Trust Model, Security Compliance, Security Guarantees).
- **Article V — Constitutional Evolution**: Part A (Governance: Evolution, Amendments, Review, Ratification, Versioning) + Part B (Continuity: Compatibility, Deprecation, Migration, Conflict Resolution) + Part C (Authority: Supremacy, Interpretation, Transitional Provisions).
- **Appendices** (no authority): A Definitions, B Normative Language, C Relationships, D Revision History. (Folder renamed `Appendix` → `Appendices`.)

Each constitutional doc uses law-style: header table → Purpose → Constitutional Principle → Definition → Responsibilities (SHALL) → Authority (MAY / SHALL NOT) → Relationships → Guarantees → Failure Handling → Invariants → Related Documents → Rationale → Future Extensions → Final Statement. **Mandatory closers: Related Documents / Rationale / Future Extensions.**

---

## 11. The documentation methodology (HOW to write well — the most actionable part)

The conversation itself is a model of good docs: numbered sections, ASCII diagrams, "instead of X do Y", concrete scenarios, plain-language analogies, "if I were building today" roadmaps. It also distilled explicit standards:

**BAS — Bible Authoring Standards (15 rules):** Specification-First (read like PCIe/UEFI/LLVM/Linux/Rust RFCs/K8s, not API docs); one purpose per doc; explain WHY; explain relationships (creator/owner/user/depends-on/failure); separate architecture from implementation; use real models (state machines, sequence/decision/layer/lifecycle diagrams); define invariants; explain failure/recovery; explain evolution (versioning/compat/migration/deprecation); define extension points; define interfaces (inputs/outputs/responsibilities/dependencies/events/evidence/policies/lifecycle); avoid repetition (cross-reference instead); every doc should teach; build vertically then connect horizontally; everything belongs to a layer.

**DQC — Documentation Quality Checklist (12/12):** WHY? responsibilities? ownership? relationships? boundaries? lifecycle? extension points? invariants? failure modes? no implementation? no repetition? implementable by a new engineer? "worthy of the Bible?" Must score 12/12.

**PSAP — Platform Service Architecture Pattern** (canonical structure for every shared service): Engine / Registry / Lifecycle / Events / Evidence / Policies / Analytics / Health / APIs / SDK.

**Authoring process:** Analyze → Discover → Improve architecture → **Save Bible discoveries as one-line notes, don't elaborate inline in the Constitution** → Design structure → Write spec → Review vs DQC → Accept.

**Constitution Rules:** each constitutional doc answers ONLY: Why authority exists? What authority established? What authority explicitly NOT established? What becomes immutable? How it interacts with the rest?

**Bible Rules:** answers How designed / works / components / protocols / algorithms / state machines / interfaces / examples / patterns / future.

**Golden warnings from the chat (the mistakes made):**
- Don't optimize for *quantity* over *authority*.
- Don't repeat the whole pipeline in every doc — cross-reference.
- Don't **mix Constitution with Bible** (the cardinal sin).
- Don't invent architecture while writing the Constitution — log it as a "Bible Discovery" and move on.
- "Would LLVM/Rust/seL4 architects consider it serious?" — the quality bar.

---

## 12. The Bible structure (layer-based, build the Master Plan first)

Recommended layered tree (organize by architectural layer, NOT feature):
```
Bible/
00-Foundations/   (BAS, DQC, PSAP, patterns, naming, terminology, design philosophy)
01-Governance/    (CLS, DGP, Review/Ratification/Version frameworks)
02-Core/          (Institution/Organization/Department/Worker/Mission/Knowledge/Execution/Runtime/Identity/Responsibility Models)
03-Institutions/  (Souu ⭐, Academy ⭐, OSYS ⭐, Future Institutions)
04-Execution/     (Runtime, Scheduler, Execution Engine, Mission/Worker Engine, Lifecycle, Recovery, Isolation, Communication, State Machines)
05-Platform/      (Trust, Compliance, Evidence, Audit, Graph Framework, CKR, AKM, Execution Isolation, Communication/Knowledge/Notification/Resource/Policy/Capability Platforms)
06-Services/      (Cryptography w/ KMS/SMS, Identity, AuthN, AuthZ, Policy, Capability, Risk, Secrets, Storage, Search, Logging, Metrics, Telemetry, Caching)
07-Domains/       (Security, Federation, Networking, Knowledge, Evolution, Learning, Resources, Marketplace, Finance, Legal, Operations, Communication)
08-Interfaces/    (SDKs, Protocols, APIs, CLI, GUI, Terminal, IDE, Remote/Federation APIs)
09-Reference/     (Reference Runtime/Institution/Organization/Worker/Mission/SDK/APIs)
10-Research/      (Future Graphs/AI/Runtime/Federation/Security, Quantum, Biology, Swarm, Distributed AI)
```
**Master Architecture Plan** (`0000-AIOS-Master-Architecture-Plan.md` + volumes 0001–0008) should be written FIRST as the index/spine, before more Bible docs, to prevent reorgs.

---

## 13. Open gaps / inconsistencies to resolve

1. **The "Bible" tier is still mostly unwritten.** DNA + Constitution exist; Physics + Bible are largely empty/to-do. This is the biggest gap.
2. **Sou↔OSYS ownership split** introduced (~line 23950) but the frozen architecture diagrams still show linear `Sou → Organizations`. Retrofit before v1.0.
3. **Pillar count** (5 vs 6 with IRS) — settle on the five-pillar model (DNA-009) and place IRS in Shared Infrastructure.
4. **"Planes" vs "Layers"** — use "Planes" consistently.
5. **AOM vs AOP** — both defined; AOP (Observability Platform) vs AOM (Object Model) — keep distinct, never confuse.
6. **No single canonical Engine list** — engine lists vary across sections. Consolidate.
7. **DNA folder restructure** proposed (Core/Philosophy/Governance) but not done.
8. **"002-Terminology.md"** was skipped then retroactively written — ensure it's complete (it is, in the DNA set).
9. **Constitution vs Bible leakage** — verify no engine/SDK names leaked into Constitution docs.
10. **Rust `sou-core` module boundaries** vs the Constitution "Engine" taxonomy need reconciling.

---

## 14. Concrete data structures / formulas / diagrams to keep

**Agent struct:**
```rust
Agent {
    id: UUID, name: "Backend Worker", runtime: ClaudeCode, model: "claude-opus-4.8",
    provider: Anthropic, role: Backend, skills: [...], permissions: [...],
    memory: ..., supervisor: ..., workspace: ..., status: Running,
}
```
**Runtime trait:** `trait Runtime { create_session(); destroy_session(); send(); receive(); interrupt(); status(); health(); }`
**Sou formula:** `Human Intent + Academy + DTS + AOP + Policies + Capabilities + Resources = Strategic Plan → OSYS → Organizations → Workers → Runtime → Execution`.
**Worker formula:** `Worker = Genome + Assigned Skills + Mission + Execution Context + Runtime + Policies + Resources + Execution Token`.
**Security six pillars:** `Identity → Trust → Governance → Protection → Execution → Accountability`.
**Final frozen stack:**
```
Human → Interaction Plane → Interaction Engine →
[Intelligence Plane: Sou → Mission Engine → Academy → OSYS → Organizations → Director→Manager→Supervisor→Worker Factory→Workers] →
Runtime Layer → [Execution Plane: Engines] → [Trust Plane: Security Kernel] → [System Plane: Linux] → Hardware
(ACF inserted as Communication Plane between Runtime Layer and Execution Engines — all comms flow through ACF.)
```
**Capability API:** `Reason() Code() Research() Trade() Communicate() See() Listen() Plan() Test()` — Sou calls capabilities; Runtime Engine maps to implementation.
**Skill YAML:** `name, description, permissions, required_tools, required_models, estimated_cost, dependencies` (+ version, capabilities, knowledge, policies, examples, benchmarks, owner, signature).
**Universal Lifecycle states:** Draft → Validation → Approval → Instantiation → Initialization → Ready → Active → Paused → Resumed → Scaling → Updating → Deprecated → Retired → Archived.
**Worker lifecycle:** Created → Initialized → Running → Blocked → Paused → Completed → Destroyed.
**Mission lifecycle:** Created → Planned → Assigned → Running → Paused → Blocked → Waiting → Review → Completed → Archived.
**Autonomy ladder:** L0 Human Controlled → L1 Human-Guided → L2 Human-Approved → L3 Supervised Autonomy → L4 Constitutional Autonomy.

---

## 15. Vocabulary alignment (chat word → constitution/DNA word)

| Chat word | Constitution / DNA word |
|---|---|
| Souu | Sou |
| Agent / Agent Session | Worker / Worker Session |
| Agent Factory | Worker Factory (under OSYS) |
| Model Router | Capability routing (ROS) |
| Resource Scheduler | Resource Engine / ROS |
| Knowledge Graph | Academy (Knowledge + Experience) |
| Skills | Skill (intelligence asset) |
| Communication Bus / IPC | ACF |
| ECC | Runtime execution compatibility layer |
| Organization System | OSYS |
| Runtime (Claude/Codex/…) | Runtime (implementation of a Capability) |
| Digital Twin | DTS |
| Genome | AGS (AI Genome System) |

---

## 16. First-page one-liners (use as openers)

- "AIOS does not replace artificial intelligence. AIOS gives artificial intelligence an operating system."
- "Linux virtualized hardware. Docker virtualized applications. Kubernetes virtualized clusters. AIOS virtualizes intelligence."
- "Sou is not an AI model, and not an agent. Sou is the autonomous operating system that plans, creates, coordinates, scales, supervises, and continuously improves an unlimited organization of AI agents running across any runtime, provider, or model."
- "The Constitution governs. The Infrastructure enables."

---

*Note: This notebook was produced by reading the full 74,817-line source via 7 parallel readers. It captures architecture, design decisions, evolution/corrections, naming, the Constitution article map, the Bible structure, and the documentation methodology (BAS/DQC/PSAP). Use it as the reference when populating the empty Constitution/Bible sections.*
