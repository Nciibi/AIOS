# AIOS Examples
## 000 — Organization Examples

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Examples |
| Document ID | EXAMPLES-000 |
| Source Laws | Law 2 — Law of Non-Execution, Law 3 — Communication, Law 6 — Lifecycle Compliance |
| Source Physics | Physics/003-Organizations.md, Physics/004-Sessions.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document provides reference examples of AIOS Organizations in operation. Each example traces a complete flow from Sou's strategic decision through Mission creation to Worker execution and result delivery. These examples are teaching tools — they illustrate how the architecture works in practice.

## Example 1: Secure Messaging App Development

### Scenario

A user asks Sou: "Build a secure messaging app with end-to-end encryption."

### Flow

```
User
  │
  ▼
Sou (Brain)
  ├── Analyzes request (Cognitive OS)
  ├── Creates Mission M-001: "Develop secure messaging application"
  ├── Defines strategic goals:
  │   ├── End-to-end encryption (Priority: Critical)
  │   ├── Rust backend (Priority: High)
  │   ├── Cross-platform UI (Priority: High)
  │   └── Security audit pass (Priority: Critical)
  │
  ▼
Mission OS creates Organization "Messaging Project" (ORG type)
  │
  ├── Sou assigns Org Genome: "Software Development Org"
  │   ├── Capability bounds: coding, review, deploy
  │   ├── Resource budget: 100K tokens, 4 workers
  │   └── Autonomy level: L2 (Delegated)
  │
  └── Departments created:
      ├── Department D-001: Backend (ODS type)
      │   ├── Worker W-001: Rust Backend (Claude Code, Opus 4.8)
      │   ├── Worker W-002: Crypto Specialist (Codex, GPT-5.5)
      │   └── Worker W-003: API Designer (Claude Code, Sonnet)
      │
      ├── Department D-002: Frontend (ODS type)
      │   ├── Worker W-004: UI Designer (Claude Code, Fable)
      │   └── Worker W-005: Cross-Platform Dev (OpenCode, Qwen 30B)
      │
      └── Department D-003: QA (ODS type)
          ├── Worker W-006: Security Tester (Codex, GPT-5.5)
          └── Worker W-007: Integration Tester (Claude Code, Sonnet)
```

### Detailed Trace

#### Step 1: Sou Reasons

```
Input: "Build a secure messaging app with end-to-end encryption"

Sou (via Cognitive OS):
  ├── Intent: Software development project
  ├── Complexity: 8/10 (cryptography, multi-platform, security-critical)
  ├── Required skills: Rust, UI, Cryptography, Networking, Testing
  ├── Recommended workers: 7
  └── Reasoning: Parallel teams needed for backend, frontend, and security
```

#### Step 2: Sou Creates Mission

```
Sou calls Mission OS:
  ├── mission_id: M-001
  ├── type: Software Development
  ├── owner: Sou
  ├── goals:
  │   ├── Goal 1: Implement E2E encryption (X25519 + AES-256-GCM)
  │   ├── Goal 2: Build Rust backend with REST API
  │   ├── Goal 3: Build cross-platform UI (Tauri + React)
  │   ├── Goal 4: Pass security audit (no critical findings)
  │   └── Goal 5: Deploy to staging
  ├── resource_budget: { tokens: 100000, workers: 7, compute: "medium" }
  └── success_criteria: All 5 goals verified by QA
```

#### Step 3: Organization Forms

```
Mission OS triggers Organization creation:

Organization "Messaging Project" (ORG-001):
  ├── state: Created → Verified → Active
  ├── departments: 3 (Backend, Frontend, QA)
  ├── workers: 7 total
  └── supervisor: Sou (via Delegation Engine)
```

#### Step 4: Workers Execute

```
Worker W-001 (Rust Backend):
  ├── assigned_task: "Implement message API endpoints"
  ├── runtime: Claude Code, model: Opus 4.8
  ├── capability_bounds: ["rust.coding", "api.design", "database.schema"]
  ├── state: Created → Planned → Assigned → Running
  ├── produces Event: Worker.ActionCompleted { worker_id, task, evidence_hash }
  └── result: "REST API implemented with 12 endpoints, tests passing"

Worker W-002 (Crypto Specialist):
  ├── assigned_task: "Implement E2E encryption module"
  ├── runtime: Codex, model: GPT-5.5
  ├── capability_bounds: ["cryptography.implement", "security.review"]
  └── result: "X25519 key exchange + AES-256-GCM implemented"

... (remaining workers execute in parallel)
```

#### Step 5: Review and Completion

```
Worker W-006 (Security Tester):
  ├── reviews all completed tasks
  ├── runs: crypto module audit, API penetration test, dependency scan
  └── report: "0 critical findings, 2 low-severity recommendations"

Worker W-007 (Integration Tester):
  ├── verifies all components work together
  ├── runs: integration test suite, end-to-end flow
  └── report: "All 47 integration tests passing"

Sou reviews final reports:
  ├── Outcome: All 5 goals met
  ├── Decision: Approve deployment
  └── Learning: Architecture pattern stored in Academy Knowledge Graph
```

#### Step 6: Sou Responds to User

```
Sou: "Your secure messaging app is ready. Here's what was built:
      - Rust backend with REST API (12 endpoints)
      - E2E encryption using X25519 + AES-256-GCM
      - Cross-platform UI built with Tauri + React
      - Security audit passed (0 critical findings)
      - Deployed to staging at https://staging.messaging.app"
```

### Organization Lifecycle for This Example

```
Created   → Mission M-001 exists
Verified  → Structure checked against Genome template
Active    → Workers hired, work begins
Active    → Workers hired, work begins
Dissolved → Workers terminated, resources returned, evidence archived
Archived  → Record preserved for audit
```

## Example 2: Autonomous Security Monitoring

### Scenario

A Security Council member configures an Organization to continuously monitor network traffic and respond to threats.

### Organization Structure

```
Organization "Security Operations Center" (OHS type — shared service)
  │
  ├── Sou assigns Mission: "Continuous network security monitoring"
  │
  ├── Department: Threat Detection (ODS)
  │   ├── Worker W-101: Packet Analyzer (OpenCode, Qwen 30B)
  │   │   ├── skill: nmap, wireshark
  │   │   ├── schedule: continuous
  │   │   └── capability: network.scan, packet.capture
  │   │
  │   ├── Worker W-102: Log Monitor (Claude Code, Sonnet)
  │   │   ├── skill: log analysis, pattern detection
  │   │   └── capability: log.ingest, anomaly.detect
  │   │
  │   └── Worker W-103: Threat Intelligence (Codex, GPT-5.5)
  │       ├── skill: threat feed ingestion, IOC matching
  │       └── capability: threat.correlate, ioc.match
  │
  ├── Department: Incident Response (ODS)
  │   ├── Worker W-104: First Responder (Claude Code, Opus 4.8)
  │   │   ├── autonomy: L2
  │   │   └── capability: incident.triage, contain.isolate
  │   │
  │   └── Worker W-105: Forensics Analyst (Codex, GPT-5.5)
  │       └── capability: forensic.collect, evidence.preserve
  │
  └── Department: Reporting (ODS)
      └── Worker W-106: Report Generator (OpenCode, Qwen 30B)
          └── capability: report.compile, alert.dispatch
```

### Key Differences from Example 1

| Aspect | Example 1 (Software Dev) | Example 2 (Security Ops) |
|--------|--------------------------|--------------------------|
| Organization type | ORG (temporary project) | OHS (persistent shared service) |
| Worker autonomy | L0–L1 (directed) | L1–L2 (delegated for response) |
| Lifespan | Mission-bound (finite) | Continuous (indefinite) |
| Resource model | Burst allocation | Reserved allocation |
| Supervision | Sou active oversight | Sou exception-based oversight |
| Output | Deliverable | Continuous state |

## Example 3: Research Organization

### Scenario

An Academy researcher needs to investigate "Quantum-safe cryptography for AIOS" — a Phase 5 research topic.

### Organization Structure

```
Organization "Quantum Crypto Research" (OPE type — temporary project)
  │
  ├── Departments: 2
  │
  ├── Department: Literature Review
  │   └── Worker W-201: Research Assistant (Hermes, Qwen 72B)
  │       ├── skill: paper.search, literature.summarize
  │       └── output: "Annotated bibliography of 47 papers"
  │
  └── Department: Experimentation
      ├── Worker W-202: Simulation Engineer (Claude Code, Opus 4.8)
      │   ├── skill: algorithm.simulate, benchmark.run
      │   └── output: "Benchmark results for 3 candidate algorithms"
      │
      └── Worker W-203: Cryptography Analyst (Codex, GPT-5.5)
          ├── skill: crypto.analyze, proof.verify
          └── output: "Security analysis report"
```

### Research Output Flow

```
Workers complete tasks
  │
  ▼
Results returned to Sou
  │
  ▼
Sou reviews and synthesizes
  │
  ▼
Knowledge artifacts submitted to Academy
  │
  ▼
Academy indexes in Knowledge Graph
  │
  ▼
Available for future missions
```

## Example 4: Federation Test — Cross-Instance Collaboration

### Scenario

Two AIOS instances (Alpha and Beta) collaborate on a shared documentation project.

### Structure

```
AIOS Instance Alpha                    AIOS Instance Beta
  │                                      │
  ├── Sou Alpha                          ├── Sou Beta
  │   └── Mission: "Write API docs"      │   └── Mission: "Review API docs"
  │       └── Worker: Documentarian      │       └── Worker: Reviewer
  │           (Claude Code, Fable)       │           (Claude Code, Sonnet)
  │                                      │
  └── Federation Gateway                 └── Federation Gateway
      └── Protocol: IXP                      └── Protocol: IXP
```

### Federation Flow

```
1. Sou Alpha creates Worker W-301: "Write API documentation"
2. Worker W-301 produces draft document
3. Sou Alpha sends draft to Sou Beta via IXP
4. Sou Beta creates Worker W-302: "Review API documentation"
5. Worker W-302 reviews and returns comments
6. Sou Beta sends review back to Sou Alpha via IXP
7. Sou Alpha incorporates feedback
8. Final document approved by both Sou instances
```

## Invariants

1. **Realistic Fidelity**: Every example must be constructible from existing Bible specifications. No example may contain architecture that does not exist in the Bible.
2. **Complete Trace**: Every example must trace a complete flow from input to output, showing all intermediate steps.
3. **Cross-Referenced**: Every component referenced in an example must link to its Bible specification.
4. **Teaching Purpose**: Examples exist to illustrate architecture, not to define it. When the Bible and an example conflict, the Bible prevails.
5. **Living Examples**: Examples evolve as the architecture evolves. Outdated examples must be updated or removed.

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou — the executive intelligence that creates missions |
| Bible/03-Institutions/Organizations/000-Overview.md | Organization architecture — this file's normative source |
| Bible/03-Institutions/Organizations/001-OOM.md | Organization Object Model — department and role structure |
| Bible/03-Institutions/Organizations/005-DOM.md | Department Object Model — sub-organization types |
| Bible/03-Institutions/Workers/000-Overview.md | Worker architecture — temporary execution units |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Mission lifecycle — 10-state model |
| Bible/02-Core/OSYS/000-Overview.md | OSYS — Organization lifecycle management |
| Bible/02-Core/ROS/005-Budget.md | ROS — resource budgets per organization |
| Bible/02-Core/Brain/Sou/003-Missions.md | Sou's mission creation process |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime — execution backends |
| Bible/04-Execution/Security/000-Overview.md | Security Council — verification infrastructure |
| Bible/06-Services/Federation/000-Overview.md | Federation — cross-instance protocols |
| Bible/02-Core/Academy/000-Overview.md | Academy — knowledge management |
