# AIOS Standards
## 001 — Naming Conventions

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Standards |
| Document ID | STD-NC-001 |
| Source Laws | All |
| Source Physics | All |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This standard defines naming conventions for all AIOS code, files, APIs, events, and configuration. Consistent naming ensures readability, discoverability, and tooling compatibility across the entire platform.

## File Naming

### Bible Documents
```
NNN-<kebab-case-name>.md
```
- 3-digit zero-padded sequence number prefix
- Kebab-case descriptive name
- Examples: `000-Overview.md`, `007-Naming-Conventions.md`

### Service Documents
```
NNN-<uppercase-abbreviation>.md
```
- 3-digit sequence number
- Service abbreviation in uppercase
- Example: `004-EVS.md`, `000-LMS.md`

### Standards, Reference, SDK
```
NNN-<kebab-case-name>.md
```
- Same pattern as Bible
- Example: `000-Design-Language.md`, `001-Audit-SDK.md`

## Code Naming

### Python (Implementation Language)
| Construct | Style | Example |
|-----------|-------|---------|
| Module/package | snake_case | `event_store`, `acf_client` |
| Class | PascalCase | `RuntimeProvider`, `SessionManager` |
| Function/method | snake_case | `create_session()`, `verify_chain()` |
| Variable | snake_case | `session_id`, `event_filter` |
| Constant | UPPER_SNAKE | `MAX_SESSIONS`, `DEFAULT_TIMEOUT` |
| Private method | _snake_case | `_emit_event()`, `_validate_token()` |
| Interface/Protocol | PascalCase with Provider suffix | `AuditProvider`, `KnowledgeProvider` |

### Database / Schema
| Construct | Style | Example |
|-----------|-------|---------|
| Entity type | snake_case | `organization`, `worker_session` |
| Field name | snake_case | `entity_id`, `created_at` |
| Index name | idx_{table}_{field} | `idx_sessions_status` |
| Event type | PascalCase | `SessionCreated`, `AuthFailed` |

### API / ACF
| Construct | Style | Example |
|-----------|-------|---------|
| ACF topic | lowercase, dot-sep | `aios.security.auth` |
| ACF topic patterns | wildcard with `*` | `aios.security.*` |
| Service name | lowercase | `lms`, `evs`, `psap` |
| RPC method | dot-notation | `session.create`, `event.query` |
| REST path | kebab-case | `/api/v1/event-store/events` |
| Query parameter | snake_case | `?event_type=auth&limit=10` |

### Configuration
| Construct | Style | Example |
|-----------|-------|---------|
| Config key | lowercase, dot-sep | `runtime.default_timeout` |
| Environment variable | UPPER_SNAKE with AIOS prefix | `AIOS_RUNTIME_TIMEOUT` |
| YAML field | snake_case | `session_timeout: 30` |

## Document IDs

Format: `{prefix}-{section}-{subcategory}-{sequence}`

| Component | Convention | Example |
|-----------|-----------|---------|
| Prefix | AIOS (system), STD (standards), REF (reference), SDK | `AIOS`, `STD`, `REF` |
| Section | BBL (Bible), PHY (Physics), SDK, REF | `BBL`, `PHY` |
| Subcategory | Section number or abbreviation | `008`, `SDK`, `NC` |
| Sequence | 3-digit zero-padded | `000`, `001` |

Examples: `AIOS-BBL-008-SDK-000`, `STD-NC-001`, `SDK-RUNTIME-000`

## Error Codes

Format: `{SOURCE}_{NNN}` where SOURCE is a 2-5 char abbreviation.

| Source | Prefix | Example |
|--------|--------|---------|
| Session | SESSION | `SESSION_001` |
| Auth | AUTH | `AUTH_002` |
| Runtime | RUNTIME | `RUNTIME_001` |
| Provider specific | CLD, OLL, TRD, etc. | `CLD_001`, `OLL_002` |
| PSAP | PSAP | `PSAP_001` |

## Identity IDs

Format: `aios:{entity_type}:{sub_type?}:{sequence}:{random_suffix}`

See `Bible/00-Foundations/007-Naming-Conventions.md` for the complete identity ID specification.

## Event Types

Format: `{Category}.{Action}` in PascalCase

| Category | Convention | Examples |
|----------|-----------|---------|
| Session lifecycle | `Session.{Action}` | `Session.Created`, `Session.Terminated` |
| Security | `{Stage}.{Action}` | `Auth.Succeeded`, `Auth.Failed` |
| Platform | `{Service}.{Action}` | `PSAP.ServiceRegistered` |
| Capability | `Capability.{Action}` | `Capability.Invoked`, `Capability.Completed` |

## Versioning

Files and services use SemVer: `MAJOR.MINOR.PATCH`
- Bible documents: `1.0` (MAJOR.MINOR only)
- SDK packages: `1.0.0` (MAJOR.MINOR.PATCH)
- Services: MAJOR.MINOR.PATCH declared in metadata

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Design-Language.md | Design language — visual and verbal conventions |
| Bible/00-Foundations/007-Naming-Conventions.md | Identity ID format specification |
| Bible/09-Reference/001-Glossary.md | Acronym registry |
| Bible/00-Foundations/006-Design-Rules.md | Code review checklist |
