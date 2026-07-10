# AIOS Complete Architecture Diagram

> **Purpose:** Comprehensive single-page ASCII diagram of the entire AIOS platform architecture — every component, layer, relationship, and data flow.
> **Source:** Bible volumes, Reference Architecture, Master API Spec
> **Legend:** `───` data/control flow · `===` constitutional authority · `┐┌┘└` containment · `()` optional/multi-instance

---

## 1. System Layering (Tiers of Immutability)

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │  TIER │ NAME          │ TRUTH               │ MUTABILITY       │ EXAMPLE   │
  ├───────┼───────────────┼─────────────────────┼──────────────────┼───────────┤
  │   1   │ DNA           │ Philosophical truth  │ Never changes    │ R1-R15    │
  │   2   │ Constitution  │ Governance truth     │ Rarely amended   │ 10 Laws   │
  │   3   │ Physics       │ Mathematical truth   │ Never violated   │ INV-001   │
  │   4   │ Bible         │ Engineering truth    │ Continuously     │ Specs     │
  │   5   │ RFC           │ Process truth        │ Transient        │ RFC-001   │
  │   6   │ Code          │ Machine truth        │ Must obey Bible  │ Rust/Go   │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Constitutional Branches (4-Branch Government)

```
  ┌──────────────────────────────────────────────────────────────────────────────────────┐
  │                        CONSTITUTION OF AIOS (10 LAWS)                               │
  │  Law 0: Supremacy  │  Law 1: Evidence  │  Law 2: Non-Execution  │  Law 3: Comm     │
  │  Law 4: Identity   │  Law 5: Autonomy  │  Law 6: Lifecycle      │  Law 7: Bounds   │
  │  Law 8: Verification-First            │  Law 9: Design DNA (R1-R15)                │
  └──────────────────────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────────┐
  │  STRATEGIC BRANCH │    │  EXECUTIVE BRANCH│    │  JUDICIAL BRANCH     │
  │  Sou (The Will)   │    │  OSYS (Org Sys)  │    │  Academy (Learning)  │
  │  ┌──────────────┐ │    │  ┌────────────┐ │    │  ┌────────────────┐  │
  │  │ Reasoning    │ │    │  │ Org Factory│ │    │  │ Evidence Ingest│  │
  │  │ Planner      │ │    │  │ Registry   │ │    │  │ KMS            │  │
  │  │ Missions     │─┼────┼─►│ Lifecycle  │ │    │  │ Knowledge Graph│  │
  │  │ Learning     │ │    │  │ Dept Mgr   │ │    │  │ Validator      │  │
  │  │ Knowledge    │ │    │  │ Gov Enforce│ │    │  │ Verifier       │  │
  │  └──────────────┘ │    │  └────────────┘ │    │  │ KEE + KCE      │  │
  │  Proposes strategy│    │  Executes ops   │    │  │ Search + API   │  │
  │  NEVER executes   │    │  via Workers    │    │  │ SDK + Distro   │  │
  └──────────────────┘    └──────────────────┘    │  │ Analytics      │  │
                                                   │  └────────────────┘  │
          │                         │             │  Learns from Events  │
          │                         │             │  NEVER executes      │
          │                         │             └──────────────────────┘
          └─────────────┬───────────┘                         │
                        │                                     │
                        ▼                                     │
          ┌────────────────────────────┐                      │
          │  SECURITY BRANCH           │◄─────────────────────┘
          │  Security Council          │  Verifies all actions
          │  ┌────────────────────┐    │  Adjudicates disputes
          │  │ 7-Stage Pipeline  │    │  Approves RFCs
          │  │ (see Section 5)   │    │  Certifies capabilities
          │  └────────────────────┘    │
          │  IDS · ATS · AZS · PS     │
          │  CCA · Risk · Exec Auth   │
          │  CSP · Audit · Sandbox    │
          │  SSM · TLM · Provenance   │
          └────────────────────────────┘
                        │
                        ▼
          ┌────────────────────────────┐
          │  NEVER executes actions    │
          │  Verifies, authorizes,     │
          │  certifies, audits ONLY    │
          └────────────────────────────┘
```

---

## 3. Full Component Architecture

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                    COMPLETE AIOS PLATFORM ARCHITECTURE                                        ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  LAYER 6: BRAIN ──── Cognitive subsystem (Sou + all cognitive services)                                     │
 │                                                                                                             │
 │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐│
 │  │  SOU (Executive Intelligence) — Identity · Personality · Goals · Executive Decisions                    ││
 │  │  Mission Creation · Delegation · Communication · Learning                                              ││
 │  │  INVARIANTS: SOU-001-007 — Sou is the only constitutional intelligence                                 ││
 │  └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘│
 │                                     │                                                                       │
 │                                     ▼                                                                       │
 │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐│
 │  │  BRAIN SERVICES (Cognitive Infrastructure)                                                             ││
 │  │                                                                                                         ││
 │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                         ││
 │  │  │Cognitive │ │Conversat │ │  Memory  │ │  LLMOS   │ │ Context  │ │ Planning │                         ││
 │  │  │   OS     │ │  ion OS  │ │   OS     │ │Inference │ │ System   │ │ System   │                         ││
 │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘                         ││
 │  │                                                                                                         ││
 │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                         ││
 │  │  │ Decision │ │   Tool   │ │ Attention│ │  Voice   │ │  Vision  │ │Personality│                         ││
 │  │  │ System   │ │  System  │ │ System   │ │  System  │ │  System  │ │ System   │                         ││
 │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘                         ││
 │  │                                                                                                         ││
 │  │  INVARIANTS: Cognitive services are stateless · LLMOS is ONLY AI path · Brain → ACF                     ││
 │  └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘│
 │  All Brain ↔ external communication flows through ACF                                                      │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 │  LAYER 5: DOMAINS ──── Specialized application domains built on core infrastructure                         │
 │                                                                                                             │
 │  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌─────────┐  ┌──────────┐ │
 │  │ TRADING │  │ SECURITY │  │ CODING  │  │  LINUX   │  │ RESEARCH │  │ COMMS  │  │ ROBOTICS│  │ EMBEDDED │ │
 │  │ Domain  │  │  Domain  │  │ Domain  │  │  Domain  │  │  Domain  │  │ Domain │  │ Domain  │  │  Domain  │ │
 │  └────┬────┘  └────┬─────┘  └────┬────┘  └────┬─────┘  └────┬─────┘  └────┬───┘  └────┬────┘  └────┬─────┘ │
 │       │             │             │            │             │             │           │             │       │
 └───────┼─────────────┼─────────────┼────────────┼─────────────┼─────────────┼───────────┼─────────────┼───────┘
         │             │             │            │             │             │           │             │
         ▼             ▼             ▼            ▼             ▼             ▼           ▼             ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  LAYER 4: FEDERATION ──── Cross-instance protocols (12 protocols, 5 trust levels)                          │
 │                                                                                                             │
 │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐│
 │  │ CXP  │ │ IXP  │ │ PXP  │ │ AIP  │ │ OXP  │ │ SXP  │ │ RXP  │ │ MXP  │ │ KXP  │ │ GXP  │ │ EXP  │ │ TXP  ││
 │  │Comm  │ │Ident │ │Platfm│ │Agent │ │ Org  │ │Securi│ │Resour│ │Mission│ │Knowle│ │Genome│ │Evidnc│ │Tradng││
 │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘│
 │  Trust: T0 Unknown → T1 Verified → T2 Partner → T3 Trusted → T4 Allied                                     │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  LAYER 3: INSTITUTIONS ──── Organizational entities that execute work                                      │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────┐                                  │
 │  │  ORGANIZATIONS (OOS - Organization Operation System)                 │                                  │
 │  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │                                  │
 │  │  │ OOM    │ │ OHS    │ │ ODS    │ │ ORG    │ │ DOM    │ │ OIS    │  │                                  │
 │  │  │ Object │ │ Health │ │ Direct │ │ Gov    │ │ Dept   │ │ Interac│  │                                  │
 │  │  │ Model  │ │ Service│ │ Service│ │ ernance│ │ Model  │ │ tion   │  │                                  │
 │  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘  │                                  │
 │  │  ┌────────┐ ┌────────┐                                               │                                  │
 │  │  │ EEE    │ │ OPE    │                                               │                                  │
 │  │  │ Engine │ │ Perform│                                               │                                  │
 │  │  │ Employ │ │ Eval   │                                               │                                  │
 │  │  └────────┘ └────────┘                                               │                                  │
 │  └──────────────────────────────────────────────────────────────────────┘                                  │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────┐                                  │
 │  │  WORKERS (WOS - Worker Operation System)                            │                                  │
 │  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌───────────────────┐ │                                  │
 │  │  │ WOM    │ │ WHS    │ │ WSS    │ │ WCS    │ │ Playbook Manager  │ │                                  │
 │  │  │ Worker │ │ Health │ │ Securi │ │ Commun │ │ ┌───────────────┐ │ │                                  │
 │  │  │ Object │ │ Service│ │ ty     │ │-ication│ │ │Created→Valid→ │ │ │                                  │
 │  │  │ Model  │ │        │ │ Service│ │ Service│ │ │Published→Depr │ │ │                                  │
 │  │  └────────┘ └────────┘ └────────┘ └────────┘ │ │→Archived       │ │ │                                  │
 │  │                                               │ └───────────────┘ │ │                                  │
 │  │  Worker Session: Created→Init→Running→Susp→Done/Destroyed         │                                  │
 │  └──────────────────────────────────────────────────────────────────────┘                                  │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────┐                                  │
 │  │  MISSIONS (MOS - Mission Operation System)                          │                                  │
 │  │  Lifecycle: Created→Planned→Assigned→Running→Completed→Archived     │                                  │
 │  │             Failed→Reviewed→Archived                                │                                  │
 │  └──────────────────────────────────────────────────────────────────────┘                                  │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  LAYER 2: CORE ENGINES ──── Strategic, learning, resource, and identity engines                            │
 │                                                                                                             │
 │  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────────────┐ │
 │  │ AGS (Agent Genome)  │  │ │ Analytics       │ │  └─────────────────────┘  │ storage, network resources │ │
 │  │ ┌─────────────────┐ │  │ │ KEE + KCE       │ │                           └─────────────────────────────┘ │
 │  │ │ Composer        │ │  │ │ SDK + API       │ │                                                             │
 │  │ │ Inheritance     │ │  │ └─────────────────┘ │  ┌─────────────────────┐                                   │
 │  │ │ Validator       │ │  │ Learns from Events  │  │ OSYS (Org System)   │                                   │
 │  │ │ Versioning      │ │  │ Produces Knowledge  │  │ ┌─────────────────┐ │                                   │
 │  │ │ Signing         │ │  └─────────────────────┘  │ │ Factory   Registry│ │                                   │
 │  │ └─────────────────┘ │                           │ │ Lifecycle  DeptMgr│ │                                   │
 │  │ Genome: Draft→Comp  │                           │ │ GovEnforce        │ │                                   │
 │  │ →Valid→Signed→Active│                           │ └─────────────────┘ │                                   │
 │  │ →Depr→Archived      │                           └─────────────────────┘                                   │
 │  └─────────────────────┘                                                                                     │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  LAYER 1: PLATFORM SERVICES ──── Infrastructure services (lifecycle, events, comms, crypto)                 │
 │                                                                                                             │
 │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
 │  │ LMS      │ │ PSAP     │ │ EVS      │ │ EPG      │ │ EIP      │ │ BG       │ │ CP       │ │ TEE      │  │
 │  │ Lifecycle│ │ Service  │ │ Event    │ │ Event    │ │ External │ │ Breaking │ │ Credential│ │ Trusted  │  │
 │  │ Mgmt     │ │ Registry │ │ Store    │ │ Proc.Graph│ │ Integrat │ │ Glass    │ │ Provider  │ │ Exec Env │  │
 │  │ 10 states│ │ Health   │ │ Raft     │ │ DAG nodes│ │ Webhook  │ │ Emergency│ │ API keys  │ │ SGX/SEV  │  │
 │  │ Event-src│ │ LB       │ │ Immutable│ │ Filter   │ │ Kafka    │ │ Override │ │ OAuth2    │ │ Attest   │  │
 │  └──────────┘ └──────────┘ └──────────┘ │ Transform│ │ MQTT     │ │ Time-bnd │ │ Certs     │ └──────────┘  │
 │  ┌──────────┐ ┌──────────┐              │ Enrich   │ │ AMQP     │ │ Multi-   │ └──────────┘                │
 │  │ Graph    │ │ State    │              │ Aggreg   │ │ REST     │ │ party     │                             │
 │  │ Framework│ │ Machine  │              └──────────┘ │ gRPC     │ └──────────┘                             │
 │  │ Graph DB │ │ Engine   │                           └──────────┘                                          │
 │  │ Traversal│ │ Generic  │  ┌────────────────────────────────────────────┐                                 │
 │  │ Analysis │ │ Guards   │  │ CROSS-CUTTING:  SMS (State Machine Store)  │                                 │
 │  └──────────┘ └──────────┘  │  TPS (Template Processor) · TPE (3rd Party) │                                 │
 │                             └────────────────────────────────────────────┘                                 │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  SECURITY COUNCIL ──── Identity, authentication, authorization, verification, audit (see Section 5)        │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │                                    7-STAGE VERIFICATION PIPELINE                                     │  │
 │  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐                  │  │
 │  │  │STAGE 1 │  │STAGE 2 │  │STAGE 3 │  │STAGE 4 │  │STAGE 5 │  │STAGE 6 │  │STAGE 7 │                  │  │
 │  │  │IDENTITY│  │AUTHENT │  │AUTHORIZ│  │POLICY  │  │CAPABIL │  │RISK    │  │EXEC    │                  │  │
 │  │  │   IDS  │─►│  ATS   │─►│  AZS   │─►│  PS    │─►│  CCA   │─►│  RE    │─►│  EAS   │                  │  │
 │  │  │ "Who?" │  │"Proof?"│  │"Allow?"│  │"Policy?"│  │"Cap?"  │  │"Risk?" │  │Token→  │                  │  │
 │  │  └────────┘  └────────┘  └────────┘  └────────┘  └────────┘  └────────┘  └────┬───┘                  │  │
 │  │                                                                                 │                       │  │
 │  │  Pipeline Invariants: Order enforced · Fail-closed · Every stage produces Event                         │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │  SUPPORTING SECURITY SERVICES                                                                       │  │
 │  │                                                                                                     │  │
 │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐          │  │
 │  │  │  CSP      │  │  AUDIT    │  │  SANDBOX  │  │   SSM     │  │   TLM     │  │ PROVENANCE│          │  │
 │  │  │ Crypto Srv│  │ Evidence  │  │ Isolation │  │ Session & │  │ Trust     │  │ Chain     │          │  │
 │  │  │ HSM integ │  │ Retention │  │ Resource  │  │ Secret Mgt│  │ Scoring   │  │ ID hist   │          │  │
 │  │  │ Sign/Verify│  │ Export    │  │ Namespace │  │ Rotation  │  │ Revocatn  │  │ Verificatn│          │  │
 │  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘          │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  ACF (ANTICIPATORY COMMUNICATION FABRIC) ──── Universal communication substrate                            │
 │                                                                                                             │
 │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐ │
 │  │ MESSAGE    │  │  ROUTER    │  │SUBSCRIPTION │  │  STREAM    │  │RELIABILITY │  │ DISTRIBUTED COORD    │ │
 │  │ BROKER     │  │ (uses PSAP)│  │  MANAGER    │  │ PROCESSOR  │  │   LAYER    │  │                      │ │
 │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐  │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────────────┐  │ │
 │  │ │Send    │ │  │ │Define  │ │  │ │Subscribe│  │  │ │Create  │ │  │ │Retry   │ │  │ │Instance Connect│  │ │
 │  │ │Recv    │ │  │ │Resolve │ │  │ │Publish  │ │  │ │Consume │ │  │ │DLQ     │ │  │ │Routing Sync    │  │ │
 │  │ │Ack     │ │  │ │Test    │ │  │ │Filter   │ │  │ │Seek    │ │  │ │Replay  │ │  │ │Bandwidth Mgmt  │  │ │
 │  │ └────────┘ │  │ └────────┘ │  │ └────────┘  │  │ └────────┘ │  │ └────────┘ │  │ └────────────────┘  │ │
 │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  └────────────┘  └──────────────────────┘ │
 │                                                                                                             │
 │  Invariants: No direct comm · Every msg authenticated · Every msg authorized · Every msg produces Event     │
 │  Topic Hierarchy: aios/{domain}/{service}/{instance}/                                                       │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  LAYER 0: RUNTIME ──── Execution providers and worker runtime                                              │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │  RUNTIME MANAGER                                                                                    │  │
 │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │  │
 │  │  │ Provider     │  │ Token        │  │ Resource     │  │ Lifecycle    │  │ Quarantine Handler   │  │  │
 │  │  │ Registry     │  │ Validator    │  │ Monitor      │  │ Manager      │  │ Isolates misbehaving │  │  │
 │  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │ providers/executions  │  │  │
 │  │                                                                           └──────────────────────┘  │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                                             │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │  EXECUTION PROVIDERS (pluggable, all implement ExecutionProvider interface via SDK)                  │  │
 │  │                                                                                                     │  │
 │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐          │  │
 │  │  │  CLAUDE   │  │   CODEX   │  │  OLLAMA   │  │  BROWSER  │  │  TRADING  │  │ ROBOTICS  │          │  │
 │  │  │ Anthropic │  │  OpenAI   │  │  Local    │  │Playwright │  │Exchange   │  │ Hardware  │          │  │
 │  │  │ Models    │  │  Codex    │  │  Models   │  │Puppeteer  │  │Connectors │  │ Actuators │          │  │
 │  │  │ Chat/Gen  │  │  Code Gen │  │ GGUF/API  │  │ Web Auto  │  │ Order Exec│  │ Control   │          │  │
 │  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘          │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                                             │
 │  SDK Interface: providerId · providerVersion · supportedActionTypes · capabilityDeclaration                  │
 │                 initialize · health · shutdown · execute · executeStream                                     │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
## 4. Entity Hierarchy & Relationships

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                  ENTITY HIERARCHY                                                        │
  │                                                                                                          │
  │  SECURITY COUNCIL (Verification Authority)           │                 │          │      │               │
  │   ├── Verifies all actions ──────┐                   │                 │          │      │               │
  │   ├── Certifies capabilities     │                   │                 │          │      │               │
  │   ├── Approves RFCs              │                   │                 │          │      │               │
  │   └── Adjudicates disputes       │                   │                 │          │      │               │
  │                                  ▼                   ▼                 ▼          ▼      ▼               │
  │                               ┌────────────────────────────────────────────────────────────────────┐      │
  │                               │  ORGANIZATION (Persistent Operational Unit)                        │      │
  │                               │  Parent defines policy bounds · Resources flow parent→child        │      │
  │                               │  Maximum 7 levels deep · Tree structure (single parent)            │      │
  │                               │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐   │      │
  │                               │  │ DEPARTMENT│  │   TEAM    │  │  WORKER   │  │   MISSION     │   │      │
```

---

## 5. Security Council Pipeline

(Content preserved from original — 7-stage verification pipeline flows)

---

## 6. Data Flow Paths

| Flow | Source | → | LLMOS | → | Provider | Description |
|------|--------|---|-------|---|----------|-------------|
| Chat | Worker |→| acf://llmos/inference |→| Claude | Interactive chat via Claude |
| Code Gen | Worker |→| acf://llmos/inference |→| Codex | Code generation via OpenAI Codex |
| Local | Worker |→| acf://llmos/inference |→| Ollama | Local model inference |
| Embed | Worker |→| LLMOS embed() |→| Provider | Embedding generation |

---

## 7. Integration Points

| Integrating Component | Interface | Purpose |
|----------------------|-----------|---------|
| Sou (via Brain) | acf://llmos/inference | Request AI inference through LLMOS |
| ROS | TokenBudget API | Budget check and reconciliation |
| Security Council | ExecutionToken | Verify execution authorization |
| EVS | Event stream | All LLMOS pipeline events |
| SSM | Credential resolution | Provider API key management |
| Memory OS | Memory retrieval API | Context memory injection |
| Legacy Workers | Runtime SDK (deprecated) | Direct provider call (migration only) |

---

## 8. Provider Interface Matrix

| Provider | ExecutionProvider | ModelProvider | Status |
|----------|------------------|---------------|--------|
| Claude | Yes | Yes | Active — dual interface |
| Codex | Yes | Yes | Active — dual interface |
| Ollama | Yes | Yes | Active — dual interface |
| Browser | Yes | No | Execution only |
| Trading | Yes | No | Execution only |
| Robotics | Yes | No | Execution only |

---

## 9. Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Brain/LLMOS/000-Overview.md | LLMOS architecture and pipeline reference |
| Bible/02-Core/Brain/LLMOS/013-Provider-SDK.md | ModelProvider interface for AI inference |
| Bible/04-Execution/Runtime/002-Claude.md | Claude provider (ModelProvider + ExecutionProvider) |
| Bible/04-Execution/Runtime/004-Ollama.md | Ollama provider (ModelProvider + ExecutionProvider) |
| APIs/000-Master-API-Spec.md | API registry with Brain and LLMOS entries |
| Bible/02-Core/Brain/000-Overview.md | Brain — cognitive container overview |
