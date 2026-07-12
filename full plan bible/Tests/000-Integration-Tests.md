# AIOS Tests
## 000 — Documentation Integration Tests

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Tests |
| Document ID | TESTS-000 |
| Source Laws | Law 4 — Evidence, Law 8 — Verification-First |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document defines the integration test strategy for the AIOS documentation corpus. Documentation tests verify structural integrity, cross-reference validity, constitutional compliance, and stub tracking across the entire Bible, Physics, Constitution, and supporting directories. These tests ensure the documentation is internally consistent, complete, and machine-verifiable.

For code-level testing (unit tests, property tests, integration tests, attack simulation, chaos tests, and benchmarks), see `tests_guide.md` and `implementation_plan.md` in the project root.

## Test Categories

### Category 1: Cross-Reference Validation

Every document's `Related Documents` table must reference only existing files. This is the most common integrity failure.

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-REF-001 | Every entry in every Related Documents table resolves to an existing `.md` file | Script: `scripts/validate_refs.sh` |
| DOC-REF-002 | Every `Supersedes` and `Superseded By` field references a valid Document ID | Script |
| DOC-REF-003 | Every `Source Physics` reference points to an existing Physics document | Script |
| DOC-REF-004 | Every `Source Laws` reference uses a valid Law identifier (Law 0–Law 9) | Script |

### Category 2: Frontmatter Completeness

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-FMT-001 | Every `.md` file in `Bible/` has a frontmatter table with all required fields | Script |
| DOC-FMT-002 | Required fields: Status, Version, Category, Document ID, Source Laws, Source Physics, Supersedes, Superseded By, Amended By | Script |
| DOC-FMT-003 | Status field is one of: Draft, Active, Deprecated, Superseded, Immutable | Script |
| DOC-FMT-004 | Version field follows SemVer (major.minor.patch) | Script |
| DOC-FMT-005 | Document ID matches the category convention (AIOS-BBL-*, AIOS-PHY-*, SDK-*, etc.) | Script |

### Category 3: Document ID Uniqueness

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-ID-001 | No two documents share the same Document ID | Script |
| DOC-ID-002 | Document IDs are sequential within each prefix (no gaps in numbering scheme) | Script |
| DOC-ID-003 | Document IDs in `Supersedes`/`Superseded By` fields exist in the corpus | Script |

### Category 4: Invariant Compliance

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-INV-001 | Every invariant referenced (e.g., PHI-004, GOV-001, SOU-001) exists in the target document | Manual + script |
| DOC-INV-002 | Invariant IDs are not duplicated across documents | Script |
| DOC-INV-003 | Every document in 02-Core/Brain/ references at least one BRAIN-* invariant | Script |
| DOC-INV-004 | Every document in 03-Institutions/ references at least one invariant from its Physics source | Script |

### Category 5: Law Compliance

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-LAW-001 | Every document's `Source Laws` references are valid (Law 0–Law 9) | Script |
| DOC-LAW-002 | No document references a Law that doesn't exist in Physics/000-Laws.md | Script |
| DOC-LAW-003 | Every document in 04-Execution/Security/ references Law 8 (Verification-First) | Script |

### Category 6: Design DNA Compliance

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-DNA-001 | Every document with a "Design DNA Compliance" section references only R1–R15 | Script |
| DOC-DNA-002 | Every Design DNA rule reference (R1–R15) matches the rule title in Physics/011-Design-DNA.md | Script |
| DOC-DNA-003 | Every institutional document (03-Institutions/) includes a Design DNA Compliance section | Script |

### Category 7: Stub Tracking

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-STUB-001 | All 0-byte files are identified and tracked | Script |
| DOC-STUB-002 | Each stub has an entry in `ideas_suggest.md` with a content plan | Manual |
| DOC-STUB-003 | Stub count is tracked over time — regressions (new stubs) trigger alerts | Script |

### Category 8: Cross-Cutting Section Compliance

| Test ID | Description | Automation |
|---------|-------------|------------|
| DOC-CC-001 | Every specification document includes Cross-Cutting Concerns section | Script |
| DOC-CC-002 | Cross-Cutting Concerns includes at minimum: Security, Evidence, Lifecycle, Capability Bounds | Script |
| DOC-CC-003 | Every document with an Events section uses event names formatted as `{Component}.{EventName}` | Script |

## Current Stub Inventory

| Path | Status | Assigned To | Target Date |
|------|--------|-------------|-------------|
| `Contributing/000-Contributing-Guide.md` | ✅ Active | — | — |
| `Examples/000-Example-Orgs.md` | ✅ Active | — | — |
| `Research/000-Phase-2-Orchestration.md` | ❌ Stub | — | — |
| `Research/001-Phase-3-Intelligence.md` | ❌ Stub | — | — |
| `Research/002-Phase-4-Integration.md` | ❌ Stub | — | — |
| `Research/003-Phase-5-Ecosystem.md` | ❌ Stub | — | — |
| `Tests/000-Integration-Tests.md` | ✅ Active | — | — |
| `DNA/` | ❌ Empty directory | — | — |

## Test Automation

### Recommended Tooling

```
Scripts in scripts/validate_docs.sh:
  ├── validate_refs()      — Check all cross-references resolve
  ├── validate_frontmatter() — Check all frontmatter tables
  ├── check_ids()          — Check Document ID uniqueness and format
  ├── check_invariants()   — Check invariant references resolve
  ├── check_stubs()        — Report 0-byte files
  └── report()             — Generate summary report
```

### Running Documentation Tests

```bash
# Full documentation validation
./scripts/validate_docs.sh --all

# Single category
./scripts/validate_docs.sh --refs

# Stub report only
./scripts/validate_docs.sh --stubs
```

### Integration with Code Tests

Documentation integrity tests should run alongside code tests in CI:

```bash
# Pre-commit hook
./scripts/validate_docs.sh --refs --stubs --fast

# Full CI pipeline
./scripts/validate_docs.sh --all
cargo test --workspace
```

## Invariants

1. **Zero Undocumented Stubs**: Every empty file in the repository must have an entry in `ideas_suggest.md` or be listed in the Stub Inventory above.
2. **Cross-Reference Completeness**: Every `Related Documents` entry must point to an existing file. Dead links are documentation bugs.
3. **Law Traceability**: Every document must trace its authority to at least one Law or Physics document. Documents without Law lineage are not constitutional.
4. **Version Discipline**: Every document must have a SemVer version. Version bumps require RFC approval. Version changes without RFC are violations.

## Related Documents

| Document | Relationship |
|---------|-------------|
| `tests_guide.md` (project root) | Code-level test specification — unit, property, integration, attack, chaos, benchmark |
| `implementation_plan.md` (project root) | Integration test crate plan — `aios_integration_tests` |
| ideas_suggest.md | Stub content suggestions and audit findings |
| Bible/00-Foundations/006-Design-Rules.md | Design rules — documentation quality standards |
| Bible/00-Foundations/007-Naming-Conventions.md | Naming conventions — file and identifier standards |
| Bible/00-Foundations/009-Versioning.md | Versioning policy — SemVer for Bible documents |
| Bible/01-Governance/003-CRP.md | RFC pipeline — how documentation changes are proposed |
| Bible/09-Reference/001-Glossary.md | AIOS terminology reference |
| Standards/002-BAS.md | Bible Authoring Standards |
| Standards/003-DQC.md | Documentation Quality Criteria |
| Contributing/000-Contributing-Guide.md | Contributor workflow — this file's companion |
