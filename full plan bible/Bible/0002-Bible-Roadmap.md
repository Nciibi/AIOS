# AIOS Bible
## 0002 — Bible Roadmap

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Root |
| Document ID | AIOS-BBL-0002 |
| Source Laws | All Laws — Bible Roadmap navigates the entire specification |
| Source Physics | Physics/000-Laws.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Bible Roadmap is the definitive navigation guide for reading and understanding the AIOS Bible. It defines the Bible's volume structure, the dependency graph between documents, the recommended reading order for different roles, and the implementation phases. Every Bible document is reachable from this roadmap.

## Bible Volume Structure

The AIOS Bible is organized into 10 volumes, each containing focused specifications:

```
00-Foundations      — Core principles, philosophy, design DNA
01-Governance       — Constitutional processes, decision gateways
02-Core             — Core engines: Sou, Academy, OSYS, ROS, DTS, AGS
03-Institutions     — Organizations, Workers, Missions
04-Execution        — Security pipeline, Runtimes, execution engines
05-Platform         — Infrastructure: LMS, State Machine, EVS, AUS, etc.
06-Services         — Platform services: ACF, Cryptography, Federation
07-Domains          — Domain-specific specifications (future)
08-Interfaces       — APIs, SDKs, protocol specifications
09-Reference        — Glossary, ADG index, decision log, migration guides
10-Research         — Future research: autonomy, ecosystem, federation
```

### Volume Dependency Graph

```
  00-Foundations
       │
       ▼
  01-Governance ──────────┐
       │                  │
       ▼                  ▼
  02-Core ──────────► 03-Institutions
       │                  │
       ▼                  ▼
  04-Execution ──────► 05-Platform
       │                  │
       ▼                  ▼
  06-Services ────────► 07-Domains
       │
       ▼
  08-Interfaces
       │
       ▼
  09-Reference ──────► 10-Research
```

Dependencies flow from top to bottom. No volume depends on a volume above it. This satisfies Design DNA R2 (Dependency Order).

### Document Dependency Graph

Documents within a volume may depend on documents in the same volume or in volumes below. The dependency graph is acyclic:

- **Foundations (00)**: Root — all other volumes depend on Foundations. Documents in Foundations depend only on each other.
- **Governance (01)**: Depends on Foundations. Documents depend on Physics and Foundations.
- **Core (02)**: Depends on Foundations and Governance. Core engines reference governance processes.
- **Institutions (03)**: Depends on Foundations, Governance, and Core. Organizations and Workers reference Sou and OSYS.
- **Execution (04)**: Depends on Foundations, Governance, and Core. Security pipeline references identity from Core.
- **Platform (05)**: Depends on Foundations, Governance, Core, and Execution. Platform infrastructure supports execution.
- **Services (06)**: Depends on Foundations, Governance, Core, Execution, and Platform. ACF depends on Identity and Security.
- **Domains (07)**: Depends on all volumes above. Domain specifications use all platform features.
- **Interfaces (08)**: Depends on Foundations, Governance, Core, Execution, Platform, and Services. APIs and SDKs expose platform capabilities.
- **Reference (09)**: Depends on all volumes above. Glossary references all terms. Decision log references all ADRs.
- **Research (10)**: Depends on Reference and all volumes above. Research extends existing specifications.

## Recommended Reading Orders

### For Architects

```
1. 00-Foundations/000-Overview.md
2. 00-Foundations/001-AIOS-Philosophy.md
3. 00-Foundations/002-Design-DNA.md
4. 01-Governance/000-Overview.md
5. 01-Governance/005-ADG.md
6. 02-Core/000-Overview.md (each core engine overview)
7. 05-Platform/000-LMS.md
8. 05-Platform/001-State-Machine.md
9. 06-Services/ACF/000-Overview.md
10. 09-Reference/000-Decision-Log.md
```

### For Developers

```
1. 00-Foundations/002-Design-DNA.md
2. 00-Foundations/003-Core-Principles.md
3. 08-Interfaces/SDK (SDK documentation for the relevant SDK)
4. 02-Core (core engine relevant to the component being built)
5. 04-Execution (execution and security for the Runtime)
6. 05-Platform (platform infrastructure used by the component)
7. 09-Reference/001-Glossary.md
```

### For Security Engineers

```
1. 04-Execution/Security/000-Overview.md
2. 04-Execution/Security/001-Architecture.md
3. 04-Execution/Security/ATS/000-Auth-Methods.md
4. 04-Execution/Security/Execution-Auth/000-EAS.md
5. 06-Services/Cryptography (all cryptography docs)
6. 01-Governance/001-CLS.md
7. 09-Reference/000-Decision-Log.md (security-related ADRs)
```

### For Governance Participants

```
1. 01-Governance/000-Overview.md
2. 01-Governance/001-CLS.md
3. 01-Governance/002-DGP.md
4. 01-Governance/003-CRP.md
5. 01-Governance/005-ADG.md
6. 00-Foundations/001-AIOS-Philosophy.md
7. 09-Reference/001-Glossary.md
```

### For Data Scientists / Academy Contributors

```
1. 02-Core/Academy/000-Overview.md
2. 02-Core/Academy/001-Architecture.md
3. 02-Core/Academy/002-KMS.md
4. 02-Core/Academy/003-Knowledge-Graph.md
5. 02-Core/Academy/014-KCE.md
6. 02-Core/Academy/013-KEE.md
7. 09-Reference/001-Glossary.md
```

## Implementation Phases

The Bible documents are implemented in phases. Each phase builds on the previous:

### Phase 1 — Foundation (Current)

**Goal**: Single-instance AIOS with core governance, basic Workers, and security pipeline.

**Documents Implemented**:
- All 00-Foundations
- All 01-Governance
- 02-Core (Sou, Academy foundation, OSYS foundation)
- 04-Execution (Security pipeline foundation)
- 05-Platform (LMS, State Machine, EVS)
- 06-Services/ACF (core routing, messages)
- 08-Interfaces/SDK (Runtime SDK, Audit SDK)
- 09-Reference (all reference documents)
- 10-Research (research roadmap)

### Phase 2 — Autonomous Operations

**Documents Added**:
- 02-Core/Academy (full knowledge pipeline: KCE, KEE, KMS)
- 02-Core/ROS (full resource orchestration)
- 03-Institutions (Organizations, Workers, Missions)
- 05-Platform (AUS, PSAP, EPG)
- 06-Services/ACF (subscriptions, streaming, reliability)

### Phase 3 — Ecosystem

**Documents Added**:
- 06-Services/Federation (IXP, CXP, federation protocols)
- 08-Interfaces/SDK (Provider SDK, Knowledge SDK)
- 07-Domains (initial domain specifications)
- Plugin system specifications

### Phase 4 — Federation

**Documents Added**:
- 06-Services/Federation (full cross-instance protocols)
- Multi-instance governance specifications
- Distributed knowledge specifications

### Phase 5 — Evolution

**Documents Added**:
- Constitutional evolution specifications
- Self-modification guards
- Generational knowledge transfer

## Stable Identifiers

Every Bible document has a stable identifier for cross-referencing:

| Prefix | Volume | Example |
|--------|--------|---------|
| BBL-000- | Foundations | BBL-000-002 (Design DNA) |
| BBL-001- | Governance | BBL-001-001 (CLS) |
| BBL-002- | Core | BBL-002-000 (Core Overview) |
| BBL-003- | Institutions | BBL-003-000 (Institutions Overview) |
| BBL-004- | Execution | BBL-004-000 (Execution Overview) |
| BBL-005- | Platform | BBL-005-000 (LMS) |
| BBL-006- | Services | BBL-006-000 (Services Overview) |
| BBL-007- | Domains | BBL-007-000 (Domains Overview) |
| BBL-008- | Interfaces | BBL-008-000 (Interfaces Overview) |
| BBL-009- | Reference | BBL-009-DEC-000 (Decision Log) |
| BBL-010- | Research | BBL-010-RES-000 (Phases 2–5) |

## Document Meta-Properties

Every Bible document uses the standard property table with these fields:

| Field | Description |
|-------|-------------|
| Status | Active, Draft, Deprecated, Superseded |
| Version | Semantic version of the document |
| Category | Bible — [Volume Name] |
| Document ID | AIOS-BBL-[vol]-[doc] |
| Source Laws | Which Laws this document derives from |
| Source Physics | Which Physics documents this document extends |
| Supersedes | Previous document this replaces (if any) |
| Superseded By | Document that replaces this (if any) |
| Amended By | RFC — every amendment requires an RFC |

## Bible Maintenance Rules

### Adding a New Document

1. Assign the next available document number within the volume
2. Add the document to the volume's Overview document table
3. Update dependency references in affected documents
4. Update this roadmap's volume structure
5. Submit RFC for the new document

### Deprecating a Document

1. Update document status to "Deprecated"
2. Add `Superseded By` field pointing to the replacement
3. Update all cross-references
4. Keep the document in the volume for historical reference

### Amendment Process

Every Bible document change follows the RFC process (see `01-Governance/003-CRP.md`):
1. RFC drafted with proposed changes
2. CRP routes to affected document owners
3. ADG review if architectural impact
4. Security Council approval
5. Implementation (document updated)
6. Verification

## Related Documents

| Document | Relationship |
|---------|-------------|
| 0001-Constitution-Roadmap.md | Constitution navigator — read this before the Bible |
| 0000-Master-Architecture-Plan.md | Master architecture — provides the architectural vision |
| 0007-Implementation-Roadmap.md | Implementation phasing — when each document is implemented |
| 01-Governance/003-CRP.md | RFC pipeline — how Bible documents are changed |
| 01-Governance/000-Overview.md | Governance overview — governance volume structure |
| 00-Foundations/000-Overview.md | Foundations overview — foundations volume structure |
| 09-Reference/001-Glossary.md | Glossary — all terms used across the Bible |
