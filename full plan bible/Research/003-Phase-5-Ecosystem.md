# AIOS Research
## 003 — Phase 5: Ecosystem & Marketplaces

| Property | Value |
|----------|-------|
| Status | Draft |
| Version | 0.1 |
| Category | Research |
| Document ID | RESEARCH-003 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Phase 5 opens AIOS to the broader ecosystem. The core question: **How does AIOS allow external contributors to extend the system without compromising constitutional integrity?**

This document explores the research required for plugin systems, skill marketplaces, provider networks, and federation as a public protocol. Phase 5 transforms AIOS from a single-instance system into a platform.

## Research Areas

### Area 1: Plugin System

External code running inside AIOS must be sandboxed, verified, and capability-bounded — never trusted by default.

**Plugin Architecture:**

```
Plugin Package
  ├── manifest.yaml (name, version, permissions, capabilities)
  ├── code/ (sandboxed execution module)
  ├── schemas/ (data schemas for plugin I/O)
  └── tests/ (conformance tests bundled by author)
          │
          ▼
AIOS Plugin Engine
  ├── Sandbox: container + seccomp + capability drop
  ├── Verifier: checks manifest against declared capabilities
  ├── Installer: validates signatures, checks dependencies
  ├── Runtime: loads plugin into isolated process
  └── Monitor: observes runtime behavior against manifest
```

**Plugin Types:**

| Type | Example | Risk Level |
|------|---------|------------|
| Skill plugin | nmap wrapper, git automation | Low |
| Tool plugin | custom code formatter, linter | Low |
| Provider plugin | Cloud API adapter, custom model host | Medium |
| Agent template | pre-configured worker genome | Medium |
| Domain plugin | FPGA design tools, bioinformatics | Medium |
| System integration | hardware monitor, kernel module | High |
| Protocol plugin | custom federation protocol | High |

**Key Questions:**
- How does the sandbox prevent plugins from exceeding declared capabilities at runtime?
- What is the certification process for plugin authors? (Identity verification? Reputation scoring?)
- How does the system handle plugin updates? (Automatic? Manual approval? Version pinning?)
- Can plugins depend on other plugins? What is the dependency resolution model?
- How are plugin performance issues isolated from the core system?

### Area 2: Skill Marketplace

A marketplace where users publish, share, and discover executable skills that workers can use.

**Skill Package Format:**

```yaml
# manifest.yaml
name: network-scan
version: 2.1.0
author: org_id:shannon-security
description: Comprehensive network scanning with nmap and custom fingerprinting
license: MIT

capabilities:
  - network.scan
  - packet.capture
  - port.discover
  - service.fingerprint

required_tools:
  - nmap (>= 7.9)
  - wireshark (>= 3.4)

required_models:
  - analysis: any (low complexity)

estimated_cost:
  per_scan: 50 tokens
  per_host: 10 tokens

security:
  sandbox: network-isolated
  network_access: restricted (scan targets only)
  data_retention: 24 hours

rating:
  quality: 4.8/5.0
  reliability: 99.2%
  total_uses: 14207
```

**Key Questions:**
- What is the economic model? (Free? Paid? Token-based? Subscription?)
- How are skills rated and reviewed? (Community reviews? Automated testing?)
- How does Sou discover the right skill for a task? (Semantic search? Skill tags? Usage statistics?)
- How are skill updates distributed without breaking existing workflows?
- What prevents malicious skills from being published?

### Area 3: Provider Network

External providers can offer compute, storage, model inference, or specialized services to AIOS instances.

**Provider Types:**

| Provider Type | Service | Integration |
|---------------|---------|-------------|
| Model Inference | LLM API access | LLMOS provider adapter |
| Compute | Cloud VMs, containers | ROS resource provider |
| Storage | Object storage, databases | ACF message persistence |
| Specialized | GPU compute, FPGA, ASIC | Runtime provider |
| Knowledge | Domain-specific datasets | Academy knowledge source |

**Provider Onboarding Flow:**

```
Provider Registration
  │
  ▼
Identity Verification (IDS/IRS)
  │
  ▼
Capability Declaration
  ├── What resources can you provide?
  ├── Under what terms? (pricing, SLA, limits?)
  └── What regions/availability zones?
  │
  ▼
Contract Establishment
  ├── Resource allocation policy
  ├── Rate limits and quotas
  └── Dispute resolution
  │
  ▼
Integration Testing
  ├── Conformance suite (provider SDK)
  ├── Load testing
  └── Security audit
  │
  ▼
Active Provider
```

**Key Questions:**
- How does Sou select between multiple providers offering the same capability? (Cost? Latency? Reliability? Reputation?)
- What is the failover model when a provider becomes unavailable?
- How are provider credentials managed? (Per-instance? Per-organization? Per-mission?)
- How does the system verify provider compliance with SLAs?
- Can AIOS instances act as providers for each other? (Peer-to-peer resource sharing)

### Area 4: Plugin SDK Maturity

The SDKs must evolve from internal tools to public, documented, and versioned interfaces.

**SDK Roadmap:**

| SDK | Current | Phase 5 Target |
|-----|---------|----------------|
| Runtime SDK | Internal use | Public, versioned, documented with examples |
| Audit SDK | Internal use | Public, plugin auditing API |
| Knowledge SDK | Internal use | Public, knowledge query and submission API |
| Provider SDK | Internal use | Public, provider onboarding toolkit |
| Skill SDK | Not started | Skill authoring toolkit |
| Plugin SDK | Not started | Plugin development framework |

**Key SDK Requirements:**
- Semantic versioning with backward compatibility guarantees
- Auto-generated API reference documentation
- Conformance test suite for each SDK
- Example projects for common use cases
- Migration guides for version bumps

**Key Questions:**
- What is the deprecation policy for SDK APIs? (Minimum notice period? Sunset period?)
- How are SDKs tested against multiple AIOS versions?
- What is the SDK distribution mechanism? (Package registries? Direct download? AIOS built-in?)
- How does the SDK handle AIOS version incompatibilities?

### Area 5: Marketplace Governance

A constitutional framework for marketplace operations.

**Governance Rules:**

| Rule | Description | Enforcement |
|------|-------------|-------------|
| MKT-001 | All plugins must declare their capability bounds | Verified at publish time |
| MKT-002 | No plugin may exceed its declared capabilities | Monitored at runtime |
| MKT-003 | Plugin authors must have verified identities | IDS verification |
| MKT-004 | All plugin code must be auditable | Source or reproducible build required |
| MKT-005 | Plugins may not access the Event Store directly | Architectural — ACF only |
| MKT-006 | Plugins cannot modify the Constitution or Physics | Constitutional — immutable |
| MKT-007 | Deputy-rated plugins require Security Council review | Human-in-the-loop before publish |
| MKT-008 | Users can block plugins by author, capability, or risk level | Per-user policy |

**Key Questions:**
- What is the dispute resolution process for marketplace conflicts? (Copyleft violations? Plagiarism? Malicious updates?)
- How does the marketplace handle takedown requests? (Security vulnerabilities? Policy violations?)
- What is the appeals process for banned plugins or authors?
- How does the marketplace interoperate with other AIOS instances? (Cross-instance marketplace sync?)

### Area 6: Federation as a Public Protocol

Phase 5 evolves federation from instance-to-instance coordination to a public protocol any AIOS instance can use.

**Protocol Stack:**

```
AIOS Public Federation Protocol
  ├── IXP: Instance Exchange Protocol (identity, trust, capability advertisement)
  ├── CXP: Conversation Exchange Protocol (cross-instance conversation relay)
  ├── KXP: Knowledge Exchange Protocol (cross-instance knowledge sharing)
  ├── RXP: Resource Exchange Protocol (cross-instance resource sharing)
  ├── MXP: Mission Exchange Protocol (cross-instance mission delegation)
  ├── OXP: Organization Exchange Protocol (cross-instance org collaboration)
  ├── GXP: Genome Exchange Protocol (cross-instance template sharing)
  ├── SXP: Skill Exchange Protocol (cross-instance skill transfer)
  ├── EXP: Evidence Exchange Protocol (cross-instance audit chain)
  ├── TXP: Token Exchange Protocol (cross-instance auth token trust)
  └── PXP: Plugin Exchange Protocol (cross-instance plugin distribution)
```

**Key Questions:**
- What is the minimum trust model for two instances to federate?
- How does federation handle instances running different AIOS versions?
- What is the security model for cross-instance protocol messages?
- How does an instance discover other instances to federate with? (DNS? DHT? Central registry?)
- Can federation be restricted by policy? (E.g., only federate with instances in the same organization)

## Open Questions

| Q-ID | Question | Priority |
|------|----------|----------|
| OQ-001 | What is the minimum viable sandbox for third-party plugin execution? | P0 |
| OQ-002 | How does the marketplace prevent supply chain attacks? | P0 |
| OQ-003 | What is the economic incentive model for plugin authors and providers? | P1 |
| OQ-004 | How does the system handle plugin version conflicts? | P1 |
| OQ-005 | What is the certification chain for providers? (Self-certify? Third-party audit?) | P1 |
| OQ-006 | How does the federation protocol ensure message authenticity? | P1 |
| OQ-007 | Can the marketplace operate without a central authority? (Federated marketplace?) | P2 |
| OQ-008 | How does the system handle abandoned plugins? (Orphan policy, takeover process) | P2 |

## RFCs Needed

| RFC | Title | Description |
|-----|-------|-------------|
| RFC-ECO-001 | Plugin SDK Specification | Plugin package format, sandbox API, manifest schema, conformance tests |
| RFC-ECO-002 | Marketplace Protocol | Package discovery, download, verification, update; rating and review system |
| RFC-ECO-003 | Provider Network Specification | Provider registration, capability advertisement, contract management, billing |
| RFC-ECO-004 | Public Federation Protocol | Cross-instance protocol stack, trust model, version negotiation |
| RFC-ECO-005 | Marketplace Governance Framework | MKT rules, dispute resolution, takedown process, appeals |

## Dependencies

| Dependency | Relationship |
|-----------|-------------|
| Bible/04-Execution/Security/Sandbox/000-Isolation.md | Sandbox — plugin isolation model |
| Bible/04-Execution/Security/000-Overview.md | Security Council — plugin certification, provider verification |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA — capability bounds certification for plugins |
| Bible/02-Core/AGS/000-Overview.md | AGS — plugin-defined genome templates |
| Bible/02-Core/Brain/Tools/000-Overview.md | Tool System — plugin-contributed tools |
| Bible/06-Services/Federation/000-Overview.md | Federation protocols — public protocol evolution |
| Bible/06-Services/ACF/000-Overview.md | ACF — plugin communication fabric |
| Bible/08-Interfaces/SDK/000-Runtime-SDK.md | Runtime SDK — public SDK evolution |
| Bible/08-Interfaces/SDK/001-Audit-SDK.md | Audit SDK — plugin auditing |
| Bible/08-Interfaces/SDK/002-Knowledge-SDK.md | Knowledge SDK — plugin knowledge access |
| Bible/05-Platform/000-LMS.md | LMS — plugin lifecycle management |
| Bible/01-Governance/000-Overview.md | Governance — marketplace constitutional framework |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/10-Research/000-Phases-2-5.md | Research roadmap — this file deepens Phase 5 |
| Bible/10-Research/002-Ecosystem.md | Ecosystem research — marketplace and plugin architecture |
| Bible/10-Research/003-Future-Topics.md | Future topics — post-Phase 5 evolution |
| Bible/0007-Implementation-Roadmap.md | Implementation phasing — Phase 5 schedule |
| Bible/0008-Future-Research.md | Research agenda and open questions |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy System — L3+ entities can publish plugins |
| Bible/07-Domains/Security/000-Overview.md | Security domain — plugin security research |
| Bible/06-Services/Federation/012-IXP.md | IXP protocol — foundation for public federation |
| ChatGPT-souuSouu Agent System Design.md | Original design vision — Agent Marketplace, Skill Marketplace |
