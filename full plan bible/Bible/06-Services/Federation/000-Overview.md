# AIOS Bible — Federation
## 000 — Federation Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services / Federation |
| Document ID | AIOS-BBL-006-FED-000 |
| Source Laws | Law 5 — Identity, Law 4 — Evidence, Law 8 — Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Federation enables communication, resource sharing, and identity resolution across AIOS instances. Each AIOS instance is autonomous and cooperates through agreed protocols. Federation is built on the ACF inter-instance bridge (06-Services/ACF/007-Distributed.md).

## Federation Model

Each AIOS instance is fully autonomous. No instance controls another. Instances cooperate through mutually agreed protocols. Trust is established through cryptographic identity exchange.

```
┌─────────────────────┐         ┌─────────────────────┐
│   Instance Alpha     │         │    Instance Beta     │
│                      │         │                      │
│  ┌──────────────┐    │  ACF    │  ┌──────────────┐    │
│  │  Federation   │◄───┼────────┼──►│  Federation   │    │
│  │  Protocols    │    │ Bridge  │  │  Protocols    │    │
│  └──────────────┘    │         │  └──────────────┘    │
│                      │         │                      │
│  ┌───┐ ┌───┐ ┌───┐  │         │  ┌───┐ ┌───┐ ┌───┐  │
│  │AIP│ │RXP│ │MXP│  │         │  │AIP│ │RXP│ │MXP│  │
│  └───┘ └───┘ └───┘  │         │  └───┘ └───┘ └───┘  │
│  ┌───┐ ┌───┐ ┌───┐  │         │  ┌───┐ ┌───┐ ┌───┐  │
│  │KXP│ │GXP│ │OXP│  │         │  │KXP│ │GXP│ │OXP│  │
│  └───┘ └───┘ └───┘  │         │  └───┘ └───┘ └───┘  │
│  ┌───┐ ┌───┐ ┌───┐  │         │  ┌───┐ ┌───┐ ┌───┐  │
│  │SXP│ │EXP│ │TXP│  │         │  │SXP│ │EXP│ │TXP│  │
│  └───┘ └───┘ └───┘  │         │  └───┘ └───┘ └───┘  │
│  ┌───┐ ┌───┐ ┌───┐  │         │  ┌───┐ ┌───┐ ┌───┐  │
│  │PXP│ │CXP│ │IXP│  │         │  │PXP│ │CXP│ │IXP│  │
│  └───┘ └───┘ └───┘  │         │  └───┘ └───┘ └───┘  │
└─────────────────────┘         └─────────────────────┘
```

## Federation Protocols

| Protocol | Name | Purpose | Doc ID |
|----------|------|---------|--------|
| AIP | Agent Interaction Protocol | Cross-instance Session communication | 001-AIP.md |
| RXP | Resource Exchange Protocol | Cross-instance resource sharing | 002-RXP.md |
| MXP | Mission Exchange Protocol | Cross-instance Mission collaboration | 003-MXP.md |
| KXP | Knowledge Exchange Protocol | Cross-instance knowledge sharing | 004-KXP.md |
| GXP | Genome Exchange Protocol | Cross-instance Genome sharing | 005-GXP.md |
| OXP | Organization Exchange Protocol | Cross-instance Organization partnership | 006-OXP.md |
| SXP | Security Exchange Protocol | Cross-instance security threat sharing | 007-SXP.md |
| EXP | Evidence Exchange Protocol | Cross-instance evidence sharing | 008-EXP.md |
| TXP | Trading Exchange Protocol | Cross-instance resource trading | 009-TXP.md |
| PXP | Platform Exchange Protocol | Cross-instance capability discovery | 010-PXP.md |
| CXP | Communication Exchange Protocol | ACF inter-instance bridge management | 011-CXP.md |
| IXP | Identity Exchange Protocol | Cross-instance identity resolution | 012-IXP.md |

## Protocol Dependency Graph

Protocols depend on lower-layer protocols. CXP (bridge) and IXP (identity) are foundational.

```
        CXP (bridge)         IXP (identity)
            │                     │
            └─────────┬───────────┘
                      │
                 PXP (discovery)
                      │
         ┌────────────┼────────────┐
         │            │            │
        AIP          OXP          SXP
      (agent)    (org partner)  (security)
         │            │
         ├──── RXP ───┤
         │  (resource)│
         │            │
         ├──── MXP ───┤
         │ (mission)  │
         │            │
         ├──── KXP ───┤
         │(knowledge) │
         │            │
         ├──── GXP ───┤
         │ (genome)   │
         │            │
         ├──── EXP ───┤
         │(evidence)  │
         │            │
         └──── TXP ───┘
           (trading)
```

## Trust Levels

Trust between instances is established through IXP and evolves through OXP partnerships:

| Level | Name | Requirements | Permissions |
|-------|------|-------------|-------------|
| T0 | Unknown | None | CXP handshake only |
| T1 | Verified | Identity verified via IXP | AIP, PXP |
| T2 | Partner | Active OXP partnership | RXP, MXP, KXP |
| T3 | Trusted | 90+ days without incident | GXP, EXP, SXP |
| T4 | Allied | Joint governance agreement | TXP, full trust |

## Federation Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| FED.InstanceDiscovered | New instance found via PXP | instance_id, trust_level, services |
| FED.BridgeEstablished | CXP bridge created | instance_id, bridge_id, config |
| FED.BridgeFailed | Bridge connection lost | instance_id, reason |
| FED.TrustLevelChanged | Instance trust level changes | instance_id, old_level, new_level |
| FED.PartnershipActivated | OXP partnership activated | instance_id, partnership_id, terms |
| FED.ProtocolVersionNegotiated | Protocol version agreed | protocol, instance_a_version, instance_b_version, negotiated |

## Federation Invariants

Stable identifiers: FED-001 through FED-005.

1. **FED-001 — Instance Autonomy**: No federation protocol may compromise instance autonomy. Each instance controls its own resources, policies, and governance.

2. **FED-002 — Mutual Authentication**: All cross-instance communication requires mutual authentication. No unauthenticated instance may participate in federation.

3. **FED-003 — Capability Scoping**: Cross-instance operations are bounded by each instance's declared capabilities. An instance cannot exceed its advertised capacity.

4. **FED-004 — Evidence Preservation**: All cross-instance operations produce evidence in both instances. Evidence is preserved independently by each instance.

5. **FED-005 — Deterministic Protocols**: Given identical inputs, federation protocols produce identical outputs. Protocol steps are defined and non-discretionary.

## Cross-Cutting Concerns

### Security
All federation protocols use mTLS with CSP encryption. Mutual authentication is mandatory. Rate limiting and audit logging are enabled by default.

### Evidence
Every cross-instance operation produces evidence in both source and destination instances. Events are linked through correlation IDs.

### Lifecycle
Federation protocols have versioned lifecycles. Instances may discover and negotiate protocol versions through CXP.

### Capability Bounds
Instances advertise their capabilities through PXP. Federation operations are bounded by advertised capacity.

### Security
All federation protocols use mTLS with CSP encryption. Mutual authentication is mandatory. Rate limiting and audit logging are enabled by default. Trust levels gate protocol access; T0 instances can only perform CXP handshake.

### Evidence
Every cross-instance operation produces evidence in both source and destination instances. Events are linked through correlation IDs. Each instance maintains independent evidence chains; cross-instance evidence is verifiable through EXP.

### Lifecycle
Federation protocols have versioned lifecycles. Instances may discover and negotiate protocol versions through CXP. Protocol version mismatch results in negotiation failure; instances must agree on a mutually supported version range.

### Capability Bounds
Instances advertise their capabilities through PXP. Federation operations are bounded by advertised capacity and trust level. An instance at T1 cannot request T3-gated operations.

### Communication
All federation traffic flows through CXP bridges. Traffic is encrypted (mTLS + CSP), authenticated, and rate-limited. ACF message routing handles multi-hop federation through intermediary instances.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R1 | Each protocol does exactly one thing. No protocol overlaps. |
| R2 | Dependency order: CXP→IXP→PXP→(AIP,OXP,SXP)→(RXP,MXP,KXP,GXP,EXP,TXP). |
| R3 | Protocol specifications defined once in their respective documents. |
| R4 | Federation connections built by CXP; protocols receive established bridges. |
| R9 | All protocol operations deterministic given identical inputs. |
| R10 | Simple request-response pattern across all 12 protocols. |
| R13 | Bridge failure → graceful degradation, no cascading failure across protocols. |
| R14 | Each operation has exactly one paved path through its protocol. No alternatives. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 06-Services/ACF/007-Distributed.md | ACF inter-instance bridge is the transport layer for federation |
| 04-Execution/Security/IDS/004-Federation.md | Identity federation for cross-instance identity |
| 06-Services/Cryptography/000-CSP.md | CSP provides encryption and signing for federation messages |
| 06-Services/Cryptography/001-CAM.md | CAM provides certificates for mTLS bridge authentication |
| 00-Foundations/001-AIOS-Philosophy.md — PHI-004, PHI-005 | Identity precedes action, verification-first applied across instances |
| 00-Foundations/003-Core-Principles.md — CPR-004, CPR-010 | Evidence immutability and privacy across instance boundaries |
