# AIOS Bible — Core
## AGS 000 — Overview (Agent Genome System)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-AGS-000 |
| Source Laws | Law 5 — Law of Capability Bounds, Law 7 — Law of Identity, Law 8 — Law of Verification-First |
| Source Physics | Physics/001-Identity.md, Physics/004-Sessions.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Agent Genome System (AGS) manages entity templates — Genomes. Every Session created in AIOS is instantiated from a Genome that defines its capabilities, bounds, policies, and provenance. A Genome is the constitutional DNA of an entity — it defines what the entity CAN be within the AIOS universe.

AGS creates, validates, composes, signs, and versions Genomes. It does NOT execute Genomes — execution happens when a Session is instantiated from a Genome by the Security Council and Runtime.

## AGS Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Agent Genome System                      │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Genome     │  │  Composer    │  │   Validator  │   │
│  │  Registry    │──│  (001)       │──│  (003)       │   │
│  │              │  │              │  │              │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │            │
│         ▼                 ▼                 ▼            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Inheritance │  │  Versioning  │  │   Signing    │   │
│  │  (002)       │  │  (004)       │  │  (005)       │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│              Security Council (verification)              │
│              IDS (identity assignment)                    │
│              LMS (lifecycle management)                   │
└──────────────────────────────────────────────────────────┘
```

## Genome Definition

A Genome is a constitutional template containing:

| Component | Description | Required |
|-----------|-------------|----------|
| genome_id | Unique identifier for the Genome | Yes |
| genome_type | Base type (Worker, User, Engine, Organization, Mission) | Yes |
| capabilities | Set of capabilities this entity may be granted | Yes |
| capability_bounds | Limits on capability usage (rate, scope, duration) | Yes |
| policies | Default policies for the entity | Yes |
| constraints | Constitutional constraints the entity must obey | Yes |
| inheritance | Parent Genome(s) this Genome derives from | No |
| overrides | Overrides to inherited traits | No |
| provenance | Source of the Genome (creator, timestamp, signature) | Yes |

## AGS Invariants

1. **Complete Definition**: Every Genome must fully define the entity's capabilities, bounds, policies, and constraints. No entity may operate without a complete Genome. (CPR-009, PHI-007)

2. **Constitutional Compliance**: Every Genome must comply with all Laws and constitutional principles. A Genome that violates a Law is invalid and cannot be instantiated. (CPR-009)

3. **Non-Execution**: AGS creates, validates, composes, signs, and versions Genomes. It does NOT instantiate Sessions. Instantiation is the Security Council's responsibility. (Law 8 — Verification-First)

4. **Provenance Tracking**: Every Genome records its provenance — who created it, when, from what source, and with what authorization. Untracked Genomes are invalid. (PHI-004, CPR-004)

5. **Immutable After Signing**: Once a Genome is signed by AGS and verified by the Security Council, it becomes immutable. Changes require a new version through the versioning system. (CPR-004)

## AGS Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `AGS.GenomeCreated` | A new Genome is registered | genome_id, genome_type, creator |
| `AGS.GenomeComposed` | A Genome is composed from template and overrides | genome_id, template_id, override_count |
| `AGS.GenomeValidated` | A Genome passes validation | genome_id, validation_result |
| `AGS.GenomeSigned` | A Genome is cryptographically signed | genome_id, signature_hash |
| `AGS.GenomeVersionCreated` | A new version of a Genome | genome_id, version, change_summary |
| `AGS.GenomeDeprecated` | A Genome is deprecated | genome_id, deprecation_reason |
| `AGS.GenomeArchived` | A Genome is archived | genome_id, retention_period |

## Cross-Cutting Concerns

### Security

Genome integrity is protected by cryptographic signatures. Every Genome must be verified by the Security Council before instantiation. AGS signing keys are managed by HSM. (Physics/008-Security.md)

### Evidence

Every AGS operation produces an Event. Genome creation, composition, validation, signing, and versioning are all recorded in the Event Store. (PHI-008, CPR-004)

### Lifecycle

Genomes follow a lifecycle: Draft → Composed → Validated → Signed → Deprecated → Archived. Session instantiation is a separate lifecycle managed by LMS. (Physics/006-Lifecycles.md)

### Capability Bounds

AGS may create, compose, validate, sign, and version Genomes. It may NOT instantiate Sessions, modify capabilities of active Sessions, or bypass constitutional constraints. (Physics/007-Capabilities.md)

### Communication

All AGS operations communicate through ACF. Genomes are requested by Security Council via ACF. Version updates are broadcast via ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | AGS focused solely on Genome management — no execution |
| R4 (Builder) | Genome construction (Composer) is separate from verification (Security Council) |
| R5 (Liskov) | All Genome types implement the Genome interface |
| R10 (Simpler Over Complex) | Genome composition uses the simplest valid inheritance model |
| R12 (Embrace Errors) | All errors have unique codes (AGS_001–099) |
| R13 (Design for Failure) | Genome registry is read-replicated — validation can proceed during partial unavailability |
| R14 (Paved Path) | Single paved path for Genome creation: compose → validate → sign |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/001-Identity.md | Identity — Sessions are instantiated with identities derived from Genomes |
| Physics/004-Sessions.md | Sessions — instantiated from Genomes |
| Physics/007-Capabilities.md | Capabilities — Genomes define capability bounds |
| Bible/02-Core/AGS/001-Composition.md | Composition — how Genomes are composed |
| Bible/02-Core/AGS/002-Inheritance.md | Inheritance — Genome hierarchy |
| Bible/02-Core/AGS/003-Validation.md | Validation — Genome validation rules |
| Bible/02-Core/AGS/004-Versioning.md | Versioning — Genome version management |
| Bible/02-Core/AGS/005-Signing.md | Signing — cryptographic signing |
| Bible/04-Execution/Security/IDS | IDS — identity registration for new Sessions |
| Bible/04-Execution/Security/ATS | ATS — authentication methods for Session types |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
