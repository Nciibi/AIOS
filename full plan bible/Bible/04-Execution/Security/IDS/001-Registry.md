# AIOS Bible — Identity Service (IDS)
## 001 — Identity Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Identity |
| Document ID | AIOS-BIBLE-IDS-001 |
| Source Laws | Law 5 — Law of Identity |
| Source Physics | Physics/001-Identity.md |

## Identity Structure

Every identity record has the following canonical structure:

| Field | Type | Mutable | Description |
|-------|------|---------|-------------|
| `identity_id` | UUIDv7 | NEVER | Globally unique constitutional identifier |
| `entity_type` | Enum | NEVER | Sou, Organization, Department, Mission, Session, Template, Runtime, Engine, User, Credential |
| `entity_id` | UUID | NEVER | The constitutional entity this identity is bound to |
| `display_name` | String | YES | Human-readable name |
| `status` | Enum | Via LMS | Created, Verified, Active, Suspended, Restored, Retired, Archived |
| `created_at` | Timestamp | NEVER | Monotonic timestamp of identity creation |
| `verified_at` | Timestamp | NEVER | When identity was verified |
| `last_activity` | Timestamp | YES | Last constitutional action timestamp |
| `metadata` | JSONB | YES | Extensible metadata (Organization, Mission, ownership context) |
| `provenance` | ProvenanceChain | NEVER | Creation provenance — who authorized the identity |
| `signature` | Hash | NEVER | Cryptographic signature of identity record |

## Entity Types

| Type | Identifier Prefix | Lifecycle Authority | Example |
|------|------------------|-------------------|---------|
| `org` | `aios:org:` | OSYS | `aios:org:001:a3f2c9d2` |
| `dept` | `aios:dept:` | OSYS | `aios:dept:002:b8e2f1a3` |
| `mission` | `aios:msn:` | OSYS | `aios:msn:003:c7d4e9f0` |
| `session` | `aios:session:` | LMS | `aios:session:worker:004:d1e2f3a4` |
| `template` | `aios:tpl:` | AGS (Templates) | `aios:tpl:005:e5f6a7b8` |
| `engine` | `aios:engine:` | OSYS (Engine lifecycle) | `aios:engine:sec:irs:001` |
| `capability` | `aios:cap:` | CCA | `aios:cap:006:f9a0b1c2` |
| `credential` | `aios:crd:` | IDS | `aios:crd:auth:007:d3e4f5a6` |
| `user` | `aios:user:` | IDS (User registry) | `aios:user:008:a1b2c3d4` |
| `entity` | `aios:ent:` | IDS (catch-all) | `aios:ent:009:e7f8a9b0` |

## Registry Operations

### createIdentity(request)

**Request**: `{ entity_type, entity_id, provenance, metadata }`

**Authorization**: The requester must have constitutional authority to create identities of the specified type. OSYS can request Organization identities. LMS can request Session identities. AGS can request Template identities. IDS itself can request Credential identities.

**Process**:
1. Validate provenance: verify the requesting entity's identity and authority
2. Validate entity_id uniqueness: no existing identity bound to this entity_id
3. Generate identity_id: `aios:{entity_type}:{entity_id_hash}:{random_suffix}`
4. Create identity record: store with status `Created`
5. Produce Event: `IdentityCreated`
6. Return identity record: `{ identity_id, status: "Created", ... }`

### listIdentities(entity_type, status, limit, offset)

**Authorization**: Security Council and Engine-level entities only. Not available to individual Sessions or Missions.

**Process**:
1. Validate authorization (requester must be Security Council or Engine)
2. Query Registry Store with pagination
3. Return identity records

### Audit Records

IDS produces an audit record for every identity operation:

- Identity ID
- Operation (create, verify, activate, suspend, restore, retire, archive)
- Timestamp (monotonic)
- Requesting entity (identity of the requester)
- Authorization token (from the Security Council, if applicable)
- Previous status and new status
- Reason (for state changes)

Audit records are Events (Physics/005-Events.md) stored in the Event Store. They are immutable and accessible through the Event Store API.

## Identity Constraints

| Constraint | Check | Enforcement |
|-----------|-------|-------------|
| Entity Precedes Implementation | Identity must be created before the entity can act | Runtime Engine refuses execution without verified identity |
| One Identity Per Entity | No two identities for the same entity_id | `entity_id` uniqueness check in Registry Store |
| Identity Is Immutable | Identity ID never changes | Immutable identity_id field, no update API for identity_id |
| Identity Precedes Authentication | Authentication requires identity | Security Council verification pipeline fails without identity |
| Identity Precedes Authorization | Authorization builds on identity | Security Council checks identity before authorization |
| Identity Is the Root of Constitutional Trust | All operations trace to identity | Every action is attributed to an identity |
| No Anonymous Constitutional Entities | Every entity must have identity | IDS denies anonymous entity creation |
| Identity Remains Traceable | Identity persists in audit after retirement | Archived identities remain in Event Store |
| Only IDS Owns Global Identity | No other entity creates identities | Security Council blocks identity creation by non-IDS entities |
| Identity Is the Foundation of the Security Pipeline | Verification pipeline starts with identity | IDS is the first check in the Security Council pipeline |