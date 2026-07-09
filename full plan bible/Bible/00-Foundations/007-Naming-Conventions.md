# AIOS Bible — Foundations
## 007 — Naming Conventions

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-007 |
| Source Laws | All |
| Source Physics | All |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Identity ID Format

Format: `aios:{entity_type}:{sequence}:{random_suffix}`

| Segment | Rules | Example |
|---------|-------|---------|
| prefix | Always `aios:` | `aios:` |
| entity_type | Lowercase, no hyphens | `org`, `session`, `engine`, `user` |
| sequence | 3-digit zero-padded number within type | `001`, `042`, `999` |
| random_suffix | 8-char hex (cryptographically random) | `a3f7c9d1` |

Examples:
- `aios:org:001:a3f2c9d2`
- `aios:session:worker:004:d1e2f3a4`
- `aios:engine:sec:irs:001`
- `aios:user:008:a1b2c3d4`

## ACF Addressing

Format: `aios:{entity_type}:{sub_type}:{instance_id}`

- `aios:engine:sec:irs:001` — IDS Engine instance 001
- `aios:engine:sec:council:001` — Security Council instance 001
- `aios:org:001:a3f2c9d2` — Organization with that identity

## Event IDs

Format: `evt:{entity_type}:{timestamp}:{random_suffix}`

- `evt:identity:1700000000:a3f2c9d1`

## Token IDs

Format: `tok:{token_type}:{random_64_hex}`

- `tok:session:a3f2c9d1b8e2f1a3c7d4e9f0...`

## File Naming

### Bible Documents

Format: `{nnn}-{Slug-Name}.md`

- `000-Overview.md`
- `001-Architecture.md`
- `002-Session-Mgmt.md`

Rules:
- 3-digit zero-padded number prefix
- Hyphen-separated PascalSlug (capitalised words joined by hyphens)
- `.md` extension
- Numbers reflect reading order within directory

### Source Code Files

| Language | Convention | Example |
|----------|-----------|---------|
| Rust | snake_case.rs | `identity_factory.rs` |
| Go | snake_case.go | `identity_factory.go` |
| TypeScript | PascalCase | `IdentityFactory.ts` |
| Tests | `<name>.test.<ext>` | `identity_factory.test.rs` |
| Integration tests | `<name>.integration.<ext>` | `pipeline.integration.ts` |

## Code Conventions

### Variables & Functions (Rust, Go)

- snake_case for functions and variables
- SCREAMING_SNAKE_CASE for constants
- CamelCase for type aliases

### Types & Structs (All Languages)

- PascalCase for types, structs, traits, interfaces
- Prefix error types with `E` (Rust: `EIdentityNotFound`)
- Prefix event types with the domain (e.g., `IdentityCreated`)

### Database

- snake_case for column names
- Table names are plural: `identities`, `organizations`, `capabilities`
- Primary key is always `id` (UUID)
- Foreign keys: `{referenced_table}_id`

### API Endpoints

- kebab-case for paths: `/api/v1/identity/verify`
- snake_case for JSON fields: `identity_id`, `entity_type`
- Enum values in PascalCase: `Created`, `Verified`, `Active`

## Directory Structure

```
aios/
├── aios-physics/           # Physics invariants (source of truth)
├── aios-bible/            # Bible specifications
├── aios-sou/               # Sou engine
├── aios-ids/               # Identity Service
├── aios-ats/               # Authentication Token Service
├── aios-azs/               # Authorization Service
├── aios-runtime/           # Runtime execution
├── aios-acf/               # ACF communication
└── aios-ros/               # Resource Orchestration Service
```

Each service directory mirrors the Bible volume structure where applicable.