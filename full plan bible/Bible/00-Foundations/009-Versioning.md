# AIOS Bible — Foundations
## 009 — Versioning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-009 |
| Source Laws | Law 0 — Law of Layering |
| Source Physics | All |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Versioning in AIOS is layered, mirroring the 5-layer architecture. Each layer has its own versioning scheme. Versions across layers are aligned through a release process.

## Layer Versioning

### 1. Constitution (Layer 1)

**Scheme**: Major.Minor (`v1.0`, `v1.1`, `v2.0`)

- **Major**: Constitutional amendment (RFC with Security Council approval + Sou approval)
- **Minor**: Clerical correction, clarification, or annotation (RFC with Security Council approval only)

The Constitution version is the canonical system version. AIOS v1.0 means Constitution v1.0.

### 2. Physics (Layer 2)

**Scheme**: Same as Constitution. Physics documents version in lockstep with the Constitution they implement (`v1.0`, `v1.1`).

- Physics v1.0 corresponds to Constitution v1.0
- Physics v1.1 corresponds to Constitution v1.1
- Physics invariants never change within a Constitution version

### 3. Bible (Layer 3)

**Scheme**: `ConstitutionVersion.BibleRevision` (e.g., `1.0.0`, `1.0.1`, `1.1.0`)

| Part | Changes When | Example |
|------|-------------|---------|
| Constitution version | Constitution changes | `1.0.0` → `2.0.0` |
| Bible major | Breaking specification change within same Constitution | `1.0.0` → `1.1.0` |
| Bible minor | Non-breaking specification addition | `1.0.0` → `1.0.1` |

Individual Bible documents carry their own version independent of the overall Bible revision. Document version is tracked in the document's header metadata.

### 4. Implementation (Layer 4)

**Scheme**: SemVer `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking API or behaviour change (requires Bible major revision)
- **MINOR**: Backward-compatible feature addition
- **PATCH**: Bug fix, performance improvement, documentation

Each service (IDS, ATS, AZS, CCA, ROS, LMS, ACF, etc.) is independently versioned.

### 5. Runtime (Layer 5)

**Scheme**: SemVer `MAJOR.MINOR.PATCH`

Runtime providers (Claude, Codex, Ollama, etc.) are versioned according to their own release cadence. The Runtime SDK version tracks against Implementation version.

## RFC Versioning

RFCs follow a sequential numbering scheme: `RFC-NNNN` where `NNNN` is a zero-padded 4-digit sequence number.

| RFC Status | Meaning |
|-----------|---------|
| Draft | RFC is being written, not yet submitted |
| Submitted | RFC is submitted for review |
| Under Review | RFC is being discussed by the Security Council |
| Approved | RFC is approved for implementation |
| Implemented | RFC has been implemented and deployed |
| Superseded | RFC has been superseded by a newer RFC |
| Rejected | RFC was rejected and will not be implemented |

## Release Alignment

A release bundles aligned versions across all layers:

```
AIOS Release 1.0
├── Constitution v1.0    [immutable]
├── Physics v1.0       [immutable for this release]
├── Bible v1.0.3       [revision 3 of the Bible for Constitution 1.0]
├── Implementation:
│   ├── aios-ids       v1.0.3
│   ├── aios-ats       v1.0.2
│   ├── aios-azs       v1.0.1
│   ├── aios-cca       v1.0.0
│   ├── aios-ros       v1.0.4
│   └── ...            (each service independently versioned)
└── Runtime:
    ├── claude-provider  v2.1.0
    ├── codex-provider   v1.3.0
    └── ollama-provider    v0.9.2
```

## Bible Document Version Header

Every Bible document includes a version header in its frontmatter:

```
Version: 1.0
Last Amended: RFC-0042
Amended By: RFC
```

- `Version`: The document's own version (independent of Bible revision number)
- `Last Amended`: The RFC that last changed this document
- `Amended By`: Always `RFC` (Bible documents are never edited outside the RFC process)

## Deprecation Policy

1. **Bible**: Documents are never deleted. Deprecated documents are marked `Status: Deprecated` and left in place for reference.
2. **Implementation**: Deployed services maintain backward compatibility for 2 Constitution minor versions.
3. **RFCs**: Approved RFCs are never deleted. Superseded RFCs are marked as such.
4. **No breaking changes without RFC**: Any change that could break existing behaviour must go through the RFC process.