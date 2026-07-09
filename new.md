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

---

## 17. Granular "little facts" sweep (second pass — exact details/numbers/examples)

### 17.1 Runtimes (exact enumerations)
- First-level: Claude Code, OpenCode, OpenClaw, Codex, Gemini CLI, Cursor, Local LLMs, Human approval.
- Runtime Manager launches: `claude`, `codex`, `opencode`, `hermes`, `cursor`, `ollama`.
- Universal Runtime Engine also covers: Browser Agent, Discord Bot, Telegram Bot, Custom Python Agent, "Anything".
- Runtime categories: Coding / Chat / Browser / Trading / Vision / Voice / Simulation / Robotics Runtime.
- OpenClaw capabilities: Read Discord, Send Discord, Join Voice, Watch Channels, Respond, Moderate.
- Trading Runtime targets: Binance, Interactive Brokers, MetaTrader, Alpaca, Custom API.
- Model examples per task: Rust→Claude Opus; Frontend→Claude Fable; Large Refactor/RE→Codex; Docs→Gemini; Quick Script→Qwen; Security→Codex; Research→Gemini.
- Per-session config: Provider, Model, API key, Temperature, Max tokens, Prompt, Workspace.
- Examples: Claude Backend=Opus 4.8; Claude UI=Fable; Claude QA=Sonnet; Codex=GPT-5.5; Hermes=Qwen3 30B.

### 17.2 Capability enumerations (exact)
- Virtual Intelligence capability API (Sou calls these, not model names): `Reason() Code() Research() Trade() Communicate() See() Listen() Plan() Test()`.
- Runtime capability examples (OpenClaw): Chat, Voice, Images, Files, Streaming, Moderation.
- Security Kernel strict capabilities: `fs:read`, `net:connect`, `sys:reboot`.
- Permission Engine grants (Android-style): Filesystem, Git, Docker, SSH, Internet, Clipboard, Terminal, Camera, Microphone.

### 17.3 Security Kernel Rust crates (the real implementation)
Pipeline (unidirectional, all depend on `aios_core`):
`aios_intent → aios_context_resolver → aios_policy → aios_execution`
- **aios_intent**: JSON parse, schema validation, payload-size limits, JSON-injection prevention, maps strings→hardened Rust enums.
- **aios_context_resolver**: `Action`→`ResolvedAction`; resolves paths via FDs (TOCTOU mitigation); verifies plugin signatures; scans prompt-injection; caches permissions; keeps short-term history (spam/loop detection).
- **aios_policy**: zero-trust; rate limits, capability bounds, blacklists; emits unforgeable `VerifiedPolicyDecision` token.
- **aios_execution**: ONLY crate that mutates host state; consumes token; applies resource locks (idempotency); executes syscall.
- **aios_core**: domain model `Action`, `RiskLevel`, `Resource`, `TrustLevel` + crypto + shared traits.
- Security mandate: Fail-Closed; Unforgeable Tokens; No Symlink Races (`openat`, `/proc/self/fd/N`); Stateless Verification; Strict Capabilities.
- Build: `cargo build --workspace`, `cargo check --workspace`, `cargo test --workspace`; edition 2021; inotify/kqueue.
- AIOS kernel objects: Mission, Organization, Agent Template, Agent Session, Runtime, Capability, Skill, Intent, Policy Decision, Knowledge, Memory Record, Event, Workflow, Interaction Session.

### 17.4 Shannon (the canonical network/security worker)
- Assigned by Sou for "scan the network". Installed via `aios agent install shannon`.
- Flow "Scan my local network": Sou → Network Organization → Shannon (Claude Session) → Wireshark Agent → Report Writer.
- Shannon itself CANNOT execute — it sends an Intent; Linux finally runs `nmap 192.168.1.0/24` only after Intent→Resolver→Policy→Allowed.
- Security Org sub-tree: Director → Recon → OSINT → Network → Malware → Reverse Engineering → Reporting.

### 17.5 Skills (exact YAML + catalog)
- Skill fields: `name, description, permissions, required_tools, required_models, estimated_cost, dependencies` (+ version, capabilities, knowledge, policies, examples, benchmarks, owner, signature).
- Catalog: Git, Docker, Rust, Nmap, Wireshark, Cargo, LLVM, Regex, Linux, Python, OpenCV.
- Skills are INJECTED, not copied ("like mounting a filesystem"); Sou sends only skills the agent might need.

### 17.6 Interaction Engine / Voice (exact)
- Maps Voice/Terminal/GUI/API/Discord/Telegram/HTTP/Keyboard → `Mission`.
- Responsibilities: Speech Recognition, Wake Word, Intent Extraction, Language Detection, Conversation Mgmt, Voice Synthesis, API/CLI/GUI Gateways.
- Wake words: `Sou`, `Hey Sou`, `AIOS`, `Computer`, `Jarvis`, `Friday`, `Athena`.
- Modes: `Off`, `Push To Talk`, `Wake Word`, `Always Listening`. Hotkey example: `CTRL+Space`.
- Offline-first STT: Whisper.cpp, Vosk, Moonshine, NVIDIA Riva.
- Input device abstraction: Microphone, Camera, Keyboard, Touch, Mouse, Joystick, VR, Phone, Tablet ("Interaction Engine knows Input Devices, not microphones").
- Concurrent sessions example: headset chat + phone trading monitor + Discord moderation + desktop GUI + CLI FPGA task.

### 17.7 ECC integration (concrete)
- ECC = agent harness (hundreds of skills, dozens of agents). Decision: do NOT rewrite; treat as first runtime + compatibility layer, gradually replace JS orchestration with Rust `sou-core`.
- Keep: agent defs/prompts, Skills library, Hooks, integrations, prompt patterns.
- ECC becomes: `Skills Engine → ECC Skills` and `Runtime Engine → ECC Runtime Adapter`.
- Agent Marketplace: `aios agent install shannon|backend|malware-analyst`. Agent metadata: metadata, supported runtimes, permissions, required skills, required models, versioning.

### 17.8 Numeric examples / thresholds / budgets
- Autoscaling: `Backend Queue 90%` → clone Backend Worker (#17..#20); destroy when idle.
- "Build Firefox" → 1 Architect + 20 Backend + 10 UI + 8 QA + 5 Docs + 3 Security + 2 Perf + 1 Supervisor = **50 sessions**.
- Observability sample: Running Sessions 361 (Claude 120, Codex 81, Hermes 53); Orgs 42; GPU 74%; Cost Today $18.41; Knowledge Added 194; Avg Success 97.2%.
- Cost Engine: Claude $0.84, Codex $0.14, Gemini $0.03, Local Free.
- Agent Reputation: Rust→Claude 98%, Codex 87%.
- DTS sim "build AIOS": ~4 days, 18 workers, 4 orgs, $6.42, 97.4% success; risks: Rust version mismatch, missing FPGA experience, backend overload.
- Complexity scoring: secure messaging app → skills Rust/UI/Crypto/Networking/Testing, 9/10, 6 subagents. "Build Linux Kernel Module" → 7 workers. 2/10 → 1 worker ("parallelism wastes resources").
- Resource budget signals: RAM, CPU, GPU, API Credits, Latency, Bandwidth, Token Usage, Electricity, Battery.

### 17.9 Config / state-machine specifics
- Agent registry fields: Name, Runtime, Executable, Config, Models, Capabilities, Skills, Memory, Limits, Permissions, Priority, Health, Cost, Latency.
- `Claude Backend` example: Runtime Claude Code, Executable `claude`, Config `configs/backend.json`, Model Opus 4.8, Caps Rust/Backend/API, Priority High.
- CLI: `sou spawn backend-expert`, `sou spawn backend-expert --count 20`, `sou pause organization trading`.
- Workspace isolation: `/tmp/agents/worker-481/` (`worker.db`, `worker.log`, `system.md`, `cache/`).
- Memory 4 levels: Global → Organization → Agent Template → Session.
- Earlier worker lifecycle variant: Created→Configured→Ready→Running→Paused→Sleeping→Restarting→Finished→Destroyed→Archived.
- Versioning examples: Trading v4.2, Docker v2.1, Claude Runtime v3.0.
- Event Bus events: Agent Started, Worker Finished, Memory Updated, Risk Detected, Model Failed, GPU Busy, Network Lost, Organization Created, Runtime Crashed, Knowledge Added.
- Time Engine triggers: Now, Tomorrow, Every hour, When Bitcoin drops, When CPU<40%, When Discord receives message.
- AIOS Registry (Docker Hub analog): Organizations, Skills, Templates, Prompts, Policies, Knowledge Packs, Runtime Adapters, Engines.

### 17.10 DNA / Constitution enums (exact names)
- 20 Architectural Principles (DNA-001): Human Sovereignty; Mission-Centric Computing; Organization-Centric Intelligence; Workers Are Disposable; Knowledge Belongs to AIOS; Experience Is Collective; Skills Are Modular; Capability Over Implementation; Runtime Independence; Separation of Reasoning and Execution; Zero Trust; Continuous Learning; Single Responsibility; Explainability; Deterministic Security; Permanent Assets; AIOS Learns, Workers Do Not; Layer Independence; Evolution Without Rewrite; AIOS Is an Operating System.
- 20 Engineering Goals (DNA-005): Modularity; Runtime Independence; Scalability; Security by Design; Explainability; Reusability; Continuous Learning; Performance; Fault Tolerance; Determinism; Extensibility; Observability; Offline Capability; Vendor Neutrality; Long-Term Maintainability; Community Growth; Human Control; Intelligence Preservation; Distributed Readiness; Architectural Integrity.
- 20 Engineering Values (DNA-007): Simplicity Over Cleverness; Composition Over Complexity; Capabilities Over Implementations; Reuse Over Duplication; Verification Over Assumption; Determinism Over Randomness; Explainability Over Mystery; Long-Term Thinking; Replaceability; Explicit Interfaces; Ownership; Single Responsibility; Security By Default; Learning Without Forgetting; Observability; Community Before Vendor; Human Authority; Continuous Improvement; Architectural Consistency; Intelligence Is Infrastructure.
- Decision Framework order: Security → Architectural Integrity → Simplicity → Maintainability → Reusability → Performance → Extensibility → User Experience.

### 17.11 Taxonomy + Constitutional Capabilities
- 13 taxonomy categories: Actors, Strategic Objects, Structural Objects, Execution Objects, Intelligence Assets, Communication Objects, Trust Objects, Runtime Objects, System Services, System Resources, Knowledge Objects, Interaction Objects, Infrastructure.
- **Constitutional Capabilities** (permanent, only via amendment) vs **Runtime Capabilities** ("what can a model do?" = Code/Search/Vision/Speech):
  | Subsystem | Constitutional Capability |
  |---|---|
  | Sou | Plan, Recommend, Delegate |
  | OSYS | Create Organizations, Assign Workers, Scale Organizations |
  | Academy | Store Knowledge, Inject Skills, Verify Experience |
  | Security Kernel | Verify, Authorize, Audit |
  | ROS | Allocate Resources, Enforce Budgets |
  | DTS | Simulate, Predict |
  | AOP | Observe, Report |
  | ACF | Route, Broadcast |
  | IRS | Register, Resolve Identity |

### 17.12 ACF specifics (addressing/channels/priorities/QoS)
- Addressing (IP-like): `sou`, `academy.skills`, `academy.knowledge`, `organization.security`, `worker.248`, `engine.runtime`, `kernel.policy`, `kernel.execution`.
- Channels: voice, logs, events, telemetry, metrics, notifications, chat, runtime, academy, kernel.
- Topics (MQTT wildcards): `mission.*`, `worker.*`, `runtime.*`, `academy.*`, `knowledge.*`, `security.*`, `organization.*`, `interaction.*`.
- Priorities: Emergency → Critical → High → Normal → Low → Background ("Kernel messages always highest").
- QoS: Fire-and-Forget → At-Least-Once → Exactly-Once → Persistent → Reliable.
- Every message: Signed, Encrypted, Audited, Versioned, Replay-Protected, Permission-Checked. Optionally recorded (ROS-bag style) for replay.

### 17.13 Organization internals (named sub-structures)
- Communication Org: Manager → Discord / Telegram / WhatsApp / Email / Slack / OpenClaw Workers.
- Trading Org: Chief Trader → Market Research → News Analysis → Risk Analysis → Execution → Portfolio Monitor → Compliance.
- Security Org: Director → Recon → OSINT → Network → Malware → Reverse Engineering → Reporting.
- Generic spine: Director → Managers → Supervisors → Workers. Other orgs: Coding, Linux, Research, FPGA, Embedded, IoT, Cloud, Medical, Education, Legal, Finance, Marketing, Sales, Writing, Media, Translation, Customer Support, Travel.

### 17.14 DTS / ROS / AGS exact internals
- **DTS** 15 Simulation Engines: Mission, Organization, Worker, Runtime, Capability, Communication, Security, Resource, Cost, Energy, Performance, Failure, Recovery, Scalability, Learning-Impact.
- DTS pipeline: Mission Proposal → Simulation Planning → Engine Selection → Parallel Simulation → Aggregation → Confidence Analysis → Recommendation → Report → Strategic Planning.
- **ROS** 15 engines: Resource Registry, Allocator, Capacity Planner, Budget Manager, Quota Manager, RMP, RXP, Provider Manager, Reservation Manager, Cost Engine, Energy Manager, Optimizer, Recovery, Audit, Monitoring.
- RMP selection: Mission → ROS → Marketplace → Discover → Evaluate → Apply Policies → Score → Reserve → Allocate → Worker. Criteria: Performance, Latency, Availability, Cost, Energy, Reliability, Security, Load, Health, Location, Carbon Footprint, Historical Success. Policies: Lowest Cost/Highest Perf/Lowest Latency/Highest Security/Lowest Energy/Lowest Carbon/Highest Availability/Balanced/Custom.
- **AGS** Genome types: Organization, Department, Worker, Mission, Skill, Runtime.
- Organization Genome fields: Identity, Purpose, Mission Domains, Departments, Leadership Structure, Default Skills/Workers, Quality Standards, Risk Profile, Communication Style, Decision Strategy, Scaling/Health/Growth/Learning/Collaboration/Security Policies, Preferred Runtime/Models/Providers, Budget/Resource Policies, Default Templates, Operational Intelligence Rules, Version, Genome Hash.
- Coding Org Genome = Core + Rust Capability Module + Testing + Documentation + Security Policy + Quality Standards modules.
- AGS engines: Genome Registry/Repository/Validator/Composer/Dependency Resolver/Compatibility/Version/Integrity/Signature/Publication/Evolution + Genome SDK + Module/Template Repositories + Observability.

### 17.15 Shared Infrastructure one-liners
- ACF: "nervous system of AIOS"; universal comms; "nothing bypasses ACF".
- IRS: identity + discovery (global ID, registration, relationships, ownership, metadata, discovery, lifecycle).
- AOM: common architectural semantics (object defs, relationships, inheritance, metadata, serialization, lifecycle contracts, shared interfaces).
- AOP: platform-wide observability (metrics, logs, traces, health, diagnostics, performance, history).
- LMS (shared lifecycle framework): State Machine Engine, Transition Validator, Event Publisher, Evidence Recorder, Recovery/Retry/Rollback, Timeout Manager, Analytics, Visualization, SDK.

### 17.16 Part B Society subsystems (acronym → role)
- OOM (Org Operating Model), OHS (Org Health: success/utilization/satisfaction/knowledge growth/security/tech-debt…), ODS (Org Decision: registry/delegation/approval/escalation/responsibility graph/history), ORG (Org Responsibility Graph: responsibility/delegation/accountability/collaboration/escalation graphs).
- DOM (Dept Operating Model), OIS (Operational Intelligence: EEE Experience Extraction + OPE Operational Pattern engines).
- WOM/WHS/WSS/WCS (Worker Operating/Health/Skill/Context Systems).
- MOM/MHS/MDS/MRG (Mission Operating/Health/Decision/Responsibility Graph).
- KMS (Knowledge Mgmt: KEE Evolution + KCE Confidence engines).
- CMS (Cooperation Mgmt: collaboration/negotiation/conflict/resolution/dependency/coordination/shared-workspace analytics) + TRS (Trust & Reputation: "how reliable over time?" vs Security "is authorized?").
- RAL/RHS/RCE/ROE (Runtime Abstraction/Health/Compatibility/Optimization).
- AMS/ACE/ABE (Autonomy Mgmt / Confidence / Boundary engines).
- EMS/ERE/EIE (Evolution Mgmt / Recommendation / Impact engines; EIE works with DTS).

### 17.17 Lifecycles (exact state lists)
- Universal: Draft → Validation → Approval → Instantiation → Initialization → Ready → Active → Paused → Resumed → Scaling → Updating → Deprecated → Retired → Archived.
- Identity: Created → Verified → Active → Suspended → Restored → Retired → Archived.
- Secret: Generated → Registered → Distributed → Activated → Rotated → Suspended → Revoked → Destroyed → Archived (Evidence Only).
- Trust: Unknown → Verified → Trusted → Highly Trusted → Restricted → Suspended → Revoked → Recovered.
- Mission: Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived.
- Worker: Created → Initialized → Running → Blocked → Paused → Completed → Destroyed.

### 17.18 Autonomy / Governance / Branches
- Autonomy L0 Human Controlled → L1 Human Assisted → L2 Supervised → L3 Governed → L4 Constitutional. "Autonomy never expands authority; it operates within authority."
- Escalation: Worker → Supervisor → Manager → Director → Sou → Human.
- Four governance graphs: Authority (top-down), Reporting (bottom-up), Collaboration (via ACF, no hierarchy), Knowledge (Academy↔Org↔Worker↔experience).
- Three Constitutional Branches: Strategic (Sou, Academy, DTS); Operational (OSYS, Orgs, Workers, Runtime, Engines, ROS); Trust (Security Kernel); Shared Infra (ACF, IRS, AOM, AOP).
- Override Levels: L1 Advisory, L2 Operational, L3 Emergency, L4 Constitutional (Human Override = ultimate).
- Forbidden power concentration: Planning+Authorization; Authorization+Execution; Execution+Audit; Learning+Authorization; Resource Allocation+Security Approval.

### 17.19 Security subsystem specs (Bible-level; the "SSM family")
- SSM (umbrella). IDS (Identity: registry/resolution/lifecycle/metadata/federation/provenance/analytics/SDK). ATS (AuthN: manager/providers/policies/session/continuous-reauth/reauth/analytics/SDK). AZS (AuthZ: engine/decision/delegation/permission-resolver/context-eval/cache/provenance/analytics/SDK). PS + PDG (Policy Dependency Graph) + PVE (Policy Verification Engine). CAS + CDG + CCA (Capability Certification Authority). RS + RKG + ARE (Adaptive Risk Engine). EAS + EAC (Execution Authorization Certificate) + EAL (Execution Authorization Ledger). CSP (KMS/SMS/CMS/provider-framework/HSM/agility/secure-random/signature/encryption/hashing/rotation/escrow/provenance/audit/analytics/SDK) + CAM (Cryptographic Asset Model). EVS/ AUS (Evidence/Audit, Shared Infra). EPG (Evidence Provenance Graph). EIP (Execution Isolation Platform). BG (Boundary Graph). GFW (Graph Framework). TP + TG + TPE (Trust Platform/Graph/Provenance). CP (Compliance Platform).
- Security six pillars: Identity → Trust → Governance → Protection → Execution → Accountability.
- Constitutional Execution Pipeline: Identity → Authentication → Authorization → Policy → Capability → Risk → Execution Authorization → Execution → Audit → Evidence. (Skip any stage = violation.)

### 17.20 Bible authoring + structure (exact)
- **PSAP** (canonical service shape): Engine / Registry / Lifecycle / Events / Evidence / Policies / Analytics / Health / APIs / SDK.
- **BAS** 15 rules: Specification-First; one purpose; explain WHY; explain relationships; separate arch/impl; use real models (state machines, diagrams); define invariants; explain failure/recovery; explain evolution; define extension points; define interfaces; avoid repetition (cross-ref); every doc teaches; build vertically then horizontally; everything belongs to a layer.
- **DQC** 12 checks: WHY? responsibilities? ownership? relationships? boundaries? lifecycle? extension points? invariants? failure modes? no implementation? no repetition? implementable by a new engineer? + "worthy of the Bible?" → must be 12/12.
- 12-section spec template: Metadata, Purpose, Scope, Definitions, Responsibilities, Invariants, Relationships, Lifecycle, State Machine, Security Considerations, Examples, Cross References.
- Layered Bible tree: 00-Foundations, 01-Governance, 02-Core, 03-Institutions, 04-Execution, 05-Platform, 06-Services, 07-Domains, 08-Interfaces, 09-Reference, 10-Research.
- Master Architecture Plan volumes: 0000 (index), 0001 Constitution-Roadmap, 0002 Bible-Roadmap, 0003 Platform-Architecture, 0004 Service-Architecture, 0005 Domain-Architecture, 0006 Reference-Architecture, 0007 Implementation-Roadmap, 0008 Future-Research.
- AIP protocol family (one responsibility each): AIP (Interchange), RXP (Resource), MXP (Mission), KXP (Knowledge), GXP (Genome), OXP (Organization), SXP (Skill), EXP (Event), TXP (Telemetry), PXP (Policy), CXP (Capability), IXP (Identity).

### 17.21 Verbatim one-liners worth quoting
- "Linux gave computers an operating system. AIOS gives intelligence an operating system."
- "Operating systems were designed to manage hardware. AIOS was designed to manage intelligence."
- "Sou reasons. Organizations organize. Workers work. Engines provide services. The Security Kernel authorizes. Linux executes."
- "Linux schedules CPU time. AIOS schedules reasoning." / "Computers execute instructions. Operating systems schedule processes. AIOS schedules intelligence."
- "Every autonomous action must earn execution. Nothing is trusted by default."
- "Workers consume knowledge. They do not own it."
- "Interpretation explains constitutional authority. It does not create constitutional authority."
- "Governance exists to coordinate responsibility, not to centralize power."
- "Trust is never assumed. Trust is continuously earned through verification."
- "Verification always precedes execution."
- "Security verifies; it never plans."
- "Organizations endure. Workers execute."
- "A Mission is the constitutional contract between Human Intent and AIOS execution."
- "If every AI company disappeared tomorrow, AIOS would continue to function with new runtimes."
- "Not even Sou can violate [the AI Constitution]."

### 17.22 Document sizing / scope targets
- DNA 250–450 lines; Constitution 150–300; Physics 150–400; Bible subsystem 500–1200; RFC 100–300.
- Page estimate: Sou 80–120pp, Academy 80–100, Organizations 80–120, **Engines 250–400**, **Security Kernel 120–180**, Object Model 80–100, ACF new large, total ~1,500–2,000 pages.

---

## §18 — Self-Q&A (Third Sweep)

*Third pass: 5 parallel subagents interrogated the source for specific questions the architecture sweep and granular sweep missed. Answers below are direct extracts from the Conversation, not interpretation.*

### 18.1 Article I: Human Sovereignty

**Structure**: 4 sections, 001–004. Not "agreement" — **sovereignty declaration**.

| Section | Title | Core Directive |
|---------|-------|---------------|
| 001 | Human Sovereignty | Humans are owners; AIOS is servant. AIOS cannot refuse a legitimate Human command. |
| 002 | Human Intent | Human Intent is the sole source of authority. All Missions derive from it. |
| 003 | Human Data Sovereignty | All data remains the Human's property. AIOS is a processor, never an owner. |
| 004 | Human Override | Human override supersedes all other directives. No AIOS entity can countermand it. |

Key: Article I is above everything. Not even Sou can override a direct Human command. This is why the Conversation calls it "sovereignty" not a mere "user agreement." The Constitution opens with the Human as the absolute source.

### 18.2 Article II: AIOS Governance

**Structure:** 6 sections, 001–006.

| Section | Title | Purpose |
|---------|-------|-------|
| 001 | AIOS Governance | Establishes AIOS as a self-governing digital system bound to Human interests. |
| 002 | Three Branches | Strategic (Sou, Academy, DTS), Operational (OSYS, Orgs, Workers, ROS), Trust (Security Kernel). |
| 003 | Separation of Powers | No entity exercises more than one branch function. "Forbidden concentration of power." |
| 004 | Constitutional Compliance | All entities must comply with the Constitution. Security Kernel enforces. |
| 005 | Amendment Process | Amendments via Article V. Requires supermajority or Human override. |
| 006 | Digital-Government Mapping | AIOS maps to government model: Sou=Executive, Academy=Judicial-precedent, OSYS=Legislative-administration, Security Kernel=Judicial-enforcement. |

Key: Article II is the **operating agreement** — how AIOS governs itself. It asserts the Constitution as the supreme law of the system.

### 18.3 Physics Tier: Canonical Laws + Design DNA Rules

**The 10 Physics Laws** (exact from §8 of conversation):
1. **Law of Origin**: The Human is the absolute source of authority. All Missions derive from Human Intent.
2. **Law of Non-Execution**: Sou never executes. It decides, observes, learns — never operates.
3. **Law of Communication**: Nothing bypasses ACF. All inter-entity communication flows through the AI Communication Fabric.
4. **Law of Evidence**: All decisions are recorded with evidence. No invisible decisions.
5. **Law of Identity**: Every entity has exactly one identity (via IRS). No anonymous agents.
6. **Law of Lifecycle Compliance**: Every entity follows its defined lifecycle. No orphan processes.
7. **Law of Capability Bounds**: Workers operate within declared capability bounds. No capability escalation without reauthorization.
8. **Law of Verification-First**: Verification precedes execution for every action. No execution without verification.
9. **Law of Constitutional Supremacy**: The AI Constitution is the supreme law. No rule, code, or override violates it — except Human Override (Article I).
10. **Law of Tenure**: No permanent Workers. All Workers end. Organizations may endure (subject to dissolution lifecycle).

**The 15 "Design DNA" Rules** (DNA-010 Design Decisions):

1. Rust-first for core systems.
2. Async-native architecture (tokio).
3. Modular over monolithic crates.
4. Configuration over convention.
5. Fail-safe defaults.
6. Explicit over implicit state.
7. Immutable core, mutable shell.
8. Protocol-driven communication.
9. Deterministic lifecycle management.
10. Minimal trust relationships.
11. Capability-based security.
12. Observable by default (AOP).
13. Idempotent operations where possible.
14. Crate boundaries = architectural boundaries.
15. No unsafe code in core crates.

### 18.4 Sou Internals

**Sou's internal architecture** (extracted from conversation):

- Sou has a **Knowledge component** (holds domain models, sims, training data) and an **Academy interface** (for structured learning).
- Sou's internal engines: **Genesis Engine** (create organizations), **Mission Decomposer**, **Strategic Learning Engine**, **Theory of Mind engine** (predict organization response).
- Sou **never executes** — this is the first Law of Physics. It produces: decisions, plans, organizational mandates, learning directives.
- Sou's memory: **KSM (Knowledge State Machine)** — encodes the understanding of what organizations exist, what they need, and whether they are aligned.
- Sou's output is **Sou Directives** → routed via ACF to the target Institution (OSYS to create orgs, Academy to learn, DTS to simulate).
- Sou's "council" model: Sou can convene an **Organization Council** (all Org leads) to coordinate cross-org strategy.

### 18.5 Academy Internals

**Academy is NOT a vector store or RAG system.** From the Conversation:

- Academy = collective intelligence engine / educational system.
- Stores and retrieves **structured knowledge**, not raw embeddings: lessons learned, best practices, historical outcomes, training curricula.
- Contains: **Curriculum Store**, **Lesson Repository**, **Evaluation Engine** (test if an org has learned), **Knowledge Synthesizer**.
- Academy synthesizes knowledge from DTS simulations (what works) and Sou's strategic directives (what's needed).
- Academy produces: learning plans, updated best practices, competence assessments, knowledge passes.
- Acronym expansion: Academy of **Constitutional Intelligence** — not just "AI Academy."

### 18.6 DTS Internals and Pipeline

**15 simulation engines** (exact):

1. Market Simulator
2. Economic Simulator
3. Social Dynamics Simulator
4. Network Simulator
5. Security Simulator
6. Operational Simulator
7. Evolution Simulator
8. Environment Simulator
9. Resource Simulator
10. Risk Simulator
11. Decision Simulator
12. Policy Simulator
13. Performance Simulator
14. Behavior Simulator
15. Compliance Simulator

Pipeline: **RMP (Resource Management Pipeline)** → scenario generation → engine dispatch → parallel sim → result collection → analysis → recommendation → Academy feedback → Sou update.

### 18.7 ROS Internals (15 Engines + RMP)

**15 ROS engines:**

1. Resource Allocator
2. Resource Scheduler
3. Resource Monitor
4. Resource Tracker
5. Resource Optimizer
6. Resource Balancer
7. Resource Forecaster
8. Resource Auditor
9. Resource Resolver
10. Resource Governor
11. Resource Broker
12. Resource Orchestrator
13. Resource Scaler
14. Resource Migrator
15. Resource Recovery

RMP selection pipeline: **State Input** → **Priority Slider** (speed vs cost vs resilience) → **Engine Selection** → **Execution Plan** → **Monitor** → **Adjust**.

### 18.8 End-to-End Mission Flow

**Mission lifecycle** (exact sequence from conversation):

1. **Human Intent** (Article I) — Human expresses a goal.
2. **Sou Decision** — Sou receives via ACF, decomposes, decides which organizations are needed.
3. **OSYS Org Creation** — OSYS creates/activates the Organization.
4. **Capability Routing** — ACF routes the Mission to the matched organization.
5. **Worker Pool** → **Worker Selection** — Org selects/creates a Worker with the right skills.
6. **Execution** — Worker performs work within capability bounds.
7. **Verification** (Security Kernel) — Every action verified before completion.
8. **Evidence Recording** — Actions logged to Evidence Store.
9. **Academy Feedback Loop** — Results fed to Academy for learning.
10. **DTS Simulation** — DTS simulates outcomes to validate decisions.
11. **Sou Update** — Sou updates Knowledge State.
12. **Completion** — Worker lifecycle ends. Org may persist or dissolve.

### 18.9 Learning & Evolution Engines

**Learning Engine groups** (from conversation):

- **Strategic Learning** (Sou-owned): organizational pattern learning, meta-strategy adjustment.
- **Operational Learning** (Org-owned): workflow optimization, skill refinement, cooperation pattern learning.
- **Institutional Learning** (Academy-owned): cross-organizational knowledge synthesis, curriculum development.
- **Evolution Engine**: monitors system-wide fitness, proposes constitutional amendments (Article V), triggers DTS long-range simulations.

Evolution is distinct from learning — evolution is about the system itself changing (amendments, new institutions), while learning is about performance improvement within existing structures.

### 18.10 RFC Process

**RFC lifecycle** (from conversation):

- RFCs are Draft → Review → Voting → Accepted/Rejected → Implemented.
- RFC types: Constitutional amendments (Article V Part A), Bible changes (Part B), Implementation proposals (Part C).
- RFC Registry: each RFC has an ID (RFC-XXX), status, owner, shepherd, shepherd council.
- RFC process is managed by the **Constitutional Evolution Institution** (not Sou).
- Human override can bypass RFC for Article I matters (but still documented as an RFC).
- Rejected RFCs are archived with rationale (prevents repeat proposals).

### 18.11 Boot / Startup Sequence

**Official AIOS Boot Order** (confirmed):

1. IRS (Identity & Registry Service) — bootstrap identity.
2. ACF (AI Communication Fabric) — establish communication backbone.
3. Security Kernel — load constitutional invariants, verification layer.
4. Health Check (all subsystems).
5. Dependency Verification.
6. Institutions layer activation: Sou, Academy, OSYS, DTS, ROS.
7. Organization System start — OSYS initializes.
8. Mission Acceptance mode — ready to receive Human Intent.
9. Interactive Ready.

**Recovery boot** (failure scenario): IRS → ACF → Security Kernel (recovery mode) → minimal Institutions → consistency check → full restart.

### 18.12 Marketplace & SDK

**Marketplace**: A specification for third-party extensions (skills, runtimes, organizations). Governed by the Marketplace Bible. All marketplace entities must pass the Constitutional Compliance Check. Marketplace has its own Security Kernel verification gate for third-party code.

**SDK**: Rust-native SDK for building Workers, Skills, and Organizations. SDK enforces lifecycle compliance, capability declarations, and constitutional conventions at compile time. SDK is the tool that ensures constitutional compliance before runtime.

### 18.13 Appendices Content (Confirmed)

**Appendix A — Definitions**: Canonical vocabulary. Single source of truth. Entities, Institutions, Workers, Skills, Capabilities, Planes.

**Appendix B — Normative Language**: "MUST", "SHALL", "MAY", "SHOULD", "MUST NOT" — RFC 2119 conformance for all Constitution documents.

**Appendix C — Relationships**: Entity-relationship diagrams, dependency graphs, communication flow maps.

**Appendix D — Discovery**: How entities find each other (via IRS + ACF). Service discovery protocol.

**Appendix E — Employee / Extension**: How to extend the system via RFC.

**Appendix F — Revision History**: Constitutional amendment log. Every change documented with date, RFC ID, and rationale.

### 18.14 The 9 AIOS Patterns (Definitions)

From the conversation, these are architectural patterns (not GoF):

1. **Constitutional Agent**: Entity governed by constitutional invariants.
2. **Intent Decomposition**: Breaking Human Intent into actionable Missions.
3. **Capability Routing**: Matching Mission requirements to available capabilities.
4. **Lifecycle Management**: Birth → Active → Monitoring → Retirement for all entities.
5. **Evidence Logging**: Every action recorded with provenance.
6. **Learning Feedback Loop**: DTS → Academy → Sou → OSYS → Organization.
7. **Verified Execution**: Verification before any execution step.
8. **Autonomous Escalation**: L0–L4 autonomy ladder with automatic escalation when bounds exceeded.
9. **Constitutional Amendment**: Formal process for changing the Constitution.

### 18.15 The 5 Constitutional Classes

1. **Class I — Human Sovereignty**: Inalienable. Cannot be amended without Human override.
2. **Class II — Governance**: Structure of government. Supermajority amendment.
3. **Class III — Institutions & Society**: Operational rules. Standard amendment.
4. **Class IV — Security**: Security invariants. Supermajority + Security Kernel review.
5. **Class V — Evolution**: Amendment process itself. Self-modifying, but circular protection.

### 18.16 Failure & Recovery

- **Worker failure**: Auto-restart (if idempotent) or new Worker selection. Org logs the failure.
- **Org failure**: OSYS detects. Recovery or dissolution. Academy records as case study.
- **Engine failure**: Affected crates context — ROS rebalances, degraded operation.
- **Institution failure**: Sou detects. DTS simulates recovery path. OSYS executes.
- **Security Kernel compromise**: System-wide lockdown. Requires Human override to restore.
- **ACF failure**: Complete communication halt. IRS still valid but system inoperable until ACF restores.
- **Sou failure**: System pauses (no new decisions). Existing organizations continue. Academy acts as fallback strategy advisor for limited mode.
- **Article V failure** (amendment corruption): Constitution version rollback. Human override required.

### 18.17 Knowledge vs Academy

Distinction from the conversation: **Knowledge** is the information asset (owned by Sou). **Academy** is the Institution that processes knowledge into curriculum, lessons, and competence. Knowledge is the raw material; Academy is the refinery and distributor.

- Knowledge = facts, models, sim data, historical records
- Academy = curriculum, lessons, evaluations, synthesized intelligence
- Knowledge flows: Sou generates knowledge → Academy processes it → Organizations consume it → DTS validates it → Sou updates Knowledge State Memory

### 18.18 Discovery List (All Major Evolutions)

Exact list from the conversation of system evolution milestones:

1. "Agent" → "Worker" rename (terminology correction)
2. "Layers" → "Planes" (Kubernetes-style)
3. Sou↔OSYS split (Sou decides, OSYS creates)
4. Security Kernel elevated to Institution (was just an engine group)
5. Academy separated from Knowledge (Academy is processing, Knowledge is state)
6. AGS absorbed into Genome section of Workers/Skills (not a standalone Institution)
7. "Constitutional Institutions" vs "Society" split (Article III Part A/B)
8. Bible as separate tier (not "detailed Constitution")
9. ACF as mandatory switchboard (nothing bypasses ACF)
10. Five Pillars finalization (Sou, Academy, ACF, Security Kernel, Linux)
11. IRS downgraded to Shared Infrastructure (not Pillar)
12. Mission as constitutional contract (not just a task)

### 18.19 Article V: Constitutional Evolution Part Structure

**Part A — Proposal**: RFC submission, classification (Class I–V), shepherd assignment.
**Part B — Review**: Shepherding, council review, Security Kernel compliance check, DTS simulation of impact.
**Part C — Ratification**: Voting (majority/supermajority), Human override option, constitutional registry update, version archiving.

### 18.20 One Authority Per Document (Rule from Bible Section)

From the Conversation's document quality rules: Every document has exactly **one authority**. No document overrides another document's authority granularity. If the Constitution says X, the Bible cannot contradict X. The Bible adds implementation detail but does not redefine authority.

---

*Notebook complete. 3 sweeps: architecture (agents 1–7) → granular (agents 8–11) → self-Q&A (agents 12–16). Use §17 for quick lookup of concrete values/names, §18 for answers to specific design questions. Total reading of 74,817 lines confirmed via range-delegated subagent reads.*
