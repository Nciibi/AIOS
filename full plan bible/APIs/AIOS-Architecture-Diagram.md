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
          │                         │                         │
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
 │  │ SOU (Will Engine)   │  │ ACADEMY (Learning)  │  │ DTS (Decision Sys)  │  │ ROS (Resource Orchestration)│ │
 │  │ ┌─────────────────┐ │  │ ┌─────────────────┐ │  │ ┌─────────────────┐ │  │ ┌─────────────────────────┐ │ │
 │  │ │ Reasoning       │ │  │ │ Evid. Ingest    │ │  │ │Decision Evaluatr│ │  │ │ Registry    Allocator   │ │ │
 │  │ │ Planner         │ │  │ │ KMS             │ │  │ │Trust Scorer     │ │  │ │ Planner     Budget      │ │ │
 │  │ │ Missions        │ │  │ │ Knowledge Graph │ │  │ │Confidence Engine│ │  │ │ Quota       RMP         │ │ │
 │  │ │ Learning        │ │  │ │ Validator       │ │  │ │Sim Pipeline     │ │  │ │ ProviderSDK Reservation │ │ │
 │  │ │ Knowledge       │ │  │ │ Verifier        │ │  │ │Sim Engines      │ │  │ │ Cost        Energy      │ │ │
 │  │ └─────────────────┘ │  │ │ Review          │ │  │ └─────────────────┘ │  │ │ Recovery    Observabil. │ │ │
 │  │ Proposes strategy   │  │ │ Versioning      │ │  │                     │  │ │ RXP (Resource Exchange) │ │ │
 │  └─────────────────────┘  │ │ Distro          │ │  │ Evaluates decisions │  │ └─────────────────────────┘ │ │
 │                           │ │ Search          │ │  │ Scores trust       │  │                             │ │
 │  ┌─────────────────────┐  │ │ Provenance      │ │  │ Runs simulations   │  │ Manages all compute        │ │
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
```

---

## 4. Entity Hierarchy & Relationships

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                  ENTITY HIERARCHY                                                        │
  │                                                                                                          │
  │  SOU (Strategic Authority) ──────────────────────────────────────────────────────────────┐               │
  │   ├── Proposes Missions ──────────────────────────────────────────────────────────┐      │               │
  │   ├── Directs Organizations ───────────────────────────────────────────┐          │      │               │
  │   └── Consults Academy ─────────────────────────────┐                 │          │      │               │
  │                                                      │                 │          │      │               │
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
  │                               │  │ Sub-unit  │  │ Operational│  │ Temporary │  │ Unit of Work  │   │      │
  │                               │  │           │  │ unit      │  │ agent     │  │               │   │      │
  │                               │  └───────────┘  └───────────┘  └───────────┘  └───────────────┘   │      │
  │                               │                                                                   │      │
  │                               │  Worker Lifecycle (8 states)                                      │      │
  │                               │  Created → Initialized → Running → Suspended → Resumed → Running  │      │
  │                               │                                        → Completed → Destroyed    │      │
  │                               │                                                                   │      │
  │                               │  Mission Lifecycle (10 states)                                    │      │
  │                               │  Created→Planned→Assigned→Running→Completed→Archived              │      │
  │                               │                             →Failed→Reviewed→Archived              │      │
  │                               └────────────────────────────────────────────────────────────────────┘      │
  │                                                                                                          │
  │  RUNTIME (Execution Environment)                    ACADEMY (Learning Engine)                             │
  │   ├── Hosts Workers                                  ├── Ingests Events from EVS                         │
  │   ├── Enforces Sandbox (WSS)                         ├── Produces Knowledge Artifacts                    │
  │   ├── Provides Execution SDK                         ├── Validates via KMS                               │
  │   └── Reports Health to PSAP                         └── Distributes to Entities via ACF                 │
  │                                                                                                          │
  │  ACF (Communication Fabric)                          ROS (Resource Orchestration)                        │
  │   ├── All messages pass through ACF                   ├── Allocates Resource Budgets                     │
  │   ├── Every message authenticated + authorized        ├── Tracks Usage and Cost                          │
  │   └── Every message produces Event in EVS             └── Enforces Quotas                                │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. The 7-Stage Security Pipeline (Detailed)

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                              SECURITY KERNEL PIPELINE                                                │
  │                                                                                                                                            │
  │  Action Request ───► ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐       │
  │  (via ACF)           │ STAGE 1  │    │ STAGE 2  │    │ STAGE 3  │    │ STAGE 4  │    │ STAGE 5  │    │ STAGE 6  │    │ STAGE 7  │       │
  │                      │ IDENTITY │───►│AUTHENT   │───►│AUTHORIZ  │───►│ POLICY   │───►│CAPABILITY│───►│  RISK    │───►│EXEC AUTH │       │
  │                      │   IDS    │    │   ATS    │    │   AZS    │    │    PS    │    │   CCA    │    │    RE    │    │   EAS    │       │
  │                      │          │    │          │    │          │    │          │    │          │    │          │    │          │       │
  │                      │ "Who is  │    │ "Are they│    │ "Are they│    │ "Does    │    │ "Do they │    │ "What is │    │ Execution│       │
  │                      │  the     │    │  who they│    │  allowed │    │  policy   │    │  have the│    │  the     │    │ Token    │       │
  │                      │  actor?" │    │  claim?" │    │  to do   │    │  allow   │    │  capabil-│    │  risk?"  │    │ Issued   │       │
  │                      │          │    │          │    │  this?"  │    │  it?"    │    │  ity?"   │    │          │    │          │       │
  │                      │          │    │          │    │          │    │          │    │          │    │          │    │          │       │
  │                      │ EntityID │    │ Token    │    │ RBAC +   │    │ Policy   │    │ Capabili │    │ Risk     │    │ Execution│       │
  │                      │ Resolved │    │ Validated│    │ ABAC Eval│    │ Evaluated│    │ Bounds   │    │ Scored   │    │ Token    │       │
  │                      │          │    │          │    │          │    │          │    │ Checked  │    │ (0.0-1.0)│    │ Generated│       │
  │                      └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘       │
  │                           │                │               │               │               │               │               │            │
  │                      ┌────▼────┐     ┌────▼────┐     ┌────▼────┐     ┌────▼────┐     ┌────▼────┐     ┌────▼────┐     ┌────▼────┐      │
  │                      │  EVENTS │     │  EVENTS │     │  EVENTS │     │  EVENTS │     │  EVENTS │     │  EVENTS │     │  EVENTS │      │
  │                      │  (EVS)  │     │  (EVS)  │     │  (EVS)  │     │  (EVS)  │     │  (EVS)  │     │  (EVS)  │     │  (EVS)  │      │
  │                      └─────────┘     └─────────┘     └─────────┘     └─────────┘     └─────────┘     └─────────┘     └─────────┘      │
  │                                                                                                                                    │
  │  INVARIANTS:                                                                                                                       │
  │  SEC-ARC-001: Stages execute in order, no skipping                                                                                 │
  │  SEC-ARC-002: Fail-closed — any stage failure = full denial                                                                        │
  │  SEC-ARC-003: Every stage produces at least one Event in EVS                                                                       │
  │  SEC-ARC-004: Stages are independent — no shared state                                                                             │
  │  SEC-ARC-005: Deterministic evaluation (risk scoring has bounded nondeterminism)                                                   │
  │                                                                                                                                     │
  │  ┌──────────────────────────────────┐                                                                                             │
  │  │  TOKEN STRUCTURE                 │  { execution_id, entity_id, capability_bounds,                                               │
  │  │                                   │    autonomy_level, resource_budget, expires_at,                                            │
  │  │                                   │    signature[Stage1..Stage7] }                                                            │
  │  └──────────────────────────────────┘                                                                                             │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Key Data Flows

```
  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                         DATA FLOWS                                                                │
  │                                                                                                                                    │
  │  EXECUTION FLOW:                                                                                                                   │
  │  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
  │  │  Sou    │───►│  Mission│───►│   ROS   │───►│  AGS      │───►│Security  │───►│  Runtime │───►│ Provider │───►│   EVS    │      │
  │  │Proposes│    │Created  │    │Allocates│    │Creates    │    │Council   │    │  Exec    │    │  Runs    │    │Records   │      │
  │  │Mission │    │         │    │Resource │    │Worker from│    │Verifies  │    │  Action  │    │  Action  │    │  Events  │      │
  │  └─────────┘    └─────────┘    │ Budget  │    │  Genome   │    │7-Stage   │    └──────────┘    └──────────┘    └──────────┘      │
  │                                └─────────┘    └───────────┘    └──────────┘                                                       │
  │                                                                                                                                   │
  │  KNOWLEDGE FLOW:                                                                                                                   │
  │  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐                                     │
  │  │  EVS    │───►│ Academy │───►│   KMS   │───►│ Knowledge │───►│ Validate │───►│Distribute│                                     │
  │  │ Events  │    │  Ingest │    │  Store  │    │   Graph   │    │ + Verify │    │  via ACF │                                     │
  │  └─────────┘    └─────────┘    └─────────┘    └───────────┘    └──────────┘    └──────────┘                                     │
  │                                                                                                                                   │
  │  IDENTITY FLOW:                                                                                                                    │
  │  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐                                     │
  │  │Entity   │───►│   IDS   │───►│  IDS    │───►│   IDS     │───►│   IDS    │───►│   IDS    │                                     │
  │  │Created  │    │Register │    │  Verify │    │  Resolve  │    │ Lifecycle│    │Federation│                                     │
  │  └─────────┘    └─────────┘    └─────────┘    └───────────┘    └──────────┘    └──────────┘                                     │
  │                                                                                                                                   │
  │  SECURITY FLOW:                                                                                                                    │
  │  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐                      │
  │  │Action   │───►│  IDS    │───►│  ATS    │───►│   AZS     │───►│    PS    │───►│   CCA    │───►│   RE+EAS │                      │
  │  │Requested│    │ Stage 1 │    │ Stage 2 │    │  Stage 3  │    │ Stage 4  │    │ Stage 5  │    │ Stages 6-7                      │
  │  └─────────┘    └─────────┘    └─────────┘    └───────────┘    └──────────┘    └──────────┘    └──────────┘                      │
  │                                                                                                                                   │
  │  COMMUNICATION FLOW (ACF):                                                                                                        │
  │  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐                                  │
  │  │ Sender   │───►│   ACF    │───►│  Router  │───►│ Subscript.│───►│  Queue   │───►│ Receiver │                                  │
  │  │ (Auth)   │    │ Envelope │    │ (PSAP)   │    │   Match   │    │  (EVS)   │    │ (Verify) │                                  │
  │  └──────────┘    └──────────┘    └──────────┘    └───────────┘    └──────────┘    └──────────┘                                  │
  └────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Platform Invariants

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                   MUST HOLD AT ALL TIMES                                                    │
  │                                                                                                              │
  │  PLT-001  Every entity is in exactly one lifecycle state (LMS)                                               │
  │  PLT-002  Every action produces at least one Event (EVS)                                                     │
  │  PLT-003  All communication flows through ACF — no direct messaging                                          │
  │  PLT-004  Every message is signed by a verified identity (CSP + Security Kernel)                              │
  │  PLT-005  Event Store is always append-only — never mutated or deleted (EVS)                                 │
  │  PLT-006  Entity state is derivable from Event stream (EVS projection)                                       │
  │  PLT-007  Lifecycle transitions are deterministic (LMS state machine)                                        │
  │  PLT-008  Cryptographic keys never leave CSP boundary (CSP)                                                  │
  │  PLT-009  Platform components are independently verifiable (Security Kernel)                                 │
  │  PLT-010  Platform failures are isolated — no cascading failures (ACF + LMS)                                 │
  │                                                                                                              │
  │  ACF-INV-001  No direct communication — all messages pass through ACF                                        │
  │  ACF-INV-002  Every message is authenticated                                                                 │
  │  ACF-INV-003  Every message is authorized                                                                    │
  │  ACF-INV-004  Every message produces an Event                                                                │
  │  ACF-INV-005  At-least-once delivery guarantees                                                              │
  │                                                                                                              │
  │  SEC-ARC-001  Stages execute in order, no skipping                                                           │
  │  SEC-ARC-002  Fail-closed — any stage failure = full denial                                                 │
  │  SEC-ARC-003  Every stage produces at least one Event                                                        │
  │  SEC-ARC-004  Stages are independent, no shared state                                                        │
  │  SEC-ARC-005  Deterministic evaluation (bounded nondeterminism in risk scoring only)                         │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Design DNA Rules (R1-R15) — Architectural Expression

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  R1  - MODULSINGULARITY     Every module does exactly one thing                                             │
  │  R2  - DEPENDENCY ORDER     Layers depend on layers below; no circular dependencies                         │
  │  R3  - DRY                  Every concept is defined exactly once in the Bible                              │
  │  R4  - BUILDER PATTERN      Complex objects (Genomes, Tokens, Sessions) built by factories                  │
  │  R5  - LISKOV SUBSTITUTION  All ExecutionProviders interchangeable through SDK interface                    │
  │  R6  - DEPENDENCY INJECTION Security Pipeline receives services through injection                           │
  │  R7  - TESTS EXIST          Every module has unit, integration, and contract tests                          │
  │  R8  - FAST TESTS           Unit tests in milliseconds, integration in seconds                              │
  │  R9  - DETERMINISTIC        Same inputs always produce same outputs (except bounded nondeterminism)         │
  │  R10 - SIMPLER OVER COMPLEX Linear flows preferred over branching; fewer paths = fewer bugs                 │
  │  R11 - REFACTOR OVER REWRITE System evolves through refactoring, not rewrites                              │
  │  R12 - EMBRACE ERRORS       Every error has unique code, context, and escalation path                       │
  │  R13 - DESIGN FOR FAILURE   Every component assumes its dependencies will fail                              │
  │  R14 - PAVED PATH           Exactly one canonical way to perform every operation                            │
  │  R15 - OPEN/CLOSED          New providers implement SDK interface without modifying Runtime                 │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Component Count Summary

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                          COMPONENT INVENTORY                                                │
  │                                                                                                              │
  │  Constitutional Branches  . . . . . . . . .  4  (Sou, OSYS, Academy, Security Council)                      │
  │  Core Engines  . . . . . . . . . . . . . . .  5  (Sou, Academy, DTS, ROS, AGS)                              │
  │  Academy Sub-Components  . . . . . . . . . . 16  (Evid Ingest→Knowledge API)                                │
  │  Sou Sub-Components  . . . . . . . . . . . .  5  (Reasoning→Knowledge)                                      │
  │  ROS Sub-Components . . . . . . . . . . . . . 13  (Registry→RXP)                                            │
  │  DTS Sub-Components . . . . . . . . . . . . .  5  (Decision Evaluator→Sim Engines)                          │
  │  AGS Sub-Components . . . . . . . . . . . . .  5  (Composer→Signing)                                        │
  │  Security Council Sub-Components . . . . . . . 11  (IDS→SSM)                                                 │
  │  Security Pipeline Stages . . . . . . . . . .  7  (Identity→Execution Auth)                                 │
  │  Platform Services . . . . . . . . . . . . . . 10  (LMS→State Machine Engine)                               │
  │  Organizations Sub-Components . . . . . . . . .  8  (OOM→OPE)                                                │
  │  Workers Sub-Components  . . . . . . . . . . .  5  (WOM→Playbook Manager)                                   │
  │  Runtime Execution Providers . . . . . . . . .  6  (Claude→Robotics)                                        │
  │  ACF Sub-Components . . . . . . . . . . . . .  6  (Message Broker→Distributed Coord)                        │
  │  Federation Protocols . . . . . . . . . . . . 12  (CXP→TXP)                                                 │
  │  Domains . . . . . . . . . . . . . . . . . . .  9  (Trading→FPGA)                                           │
  │  ACF Canonical Topics . . . . . . . . . . . . 11  (academy.knowledge.*→system.session.*)                    │
  │  Platform Invariants . . . . . . . . . . . . . 15  (PLT-010 + ACF-INV-005 + SEC-ARC-005)                    │
  │  Design DNA Rules . . . . . . . . . . . . . . 15  (R1-Modulsingularity→R15-Open/Closed)                    │
  │                                                                                                              │
  │  TOTAL REGISTERED API ENTRIES . . . . . . . . 536  (see Master API Spec)                                    │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
