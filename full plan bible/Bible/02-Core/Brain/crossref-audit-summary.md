# Brain Sub-doc Audit Report — 67 files, 11 checks

## Severity Legend
- **Critical**: Missing required sections, banned architecture heading
- **High**: Non-standard table formats, Design DNA deviations
- **Medium**: Section naming inconsistencies
- **Low**: Minor format deviations
- **Info**: Source law variations (expected by domain)

---

## CRITICAL

### LLMOS — All 13 files lack 5 required sections
Every file in `LLMOS/` (`001-Model-Registry.md` through `013-Provider-SDK.md`) is missing:
- `## Events` section
- `## Error Cases` section
- `## Invariants` section
- `## Design DNA` section
- `## Related Documents` section

**Files affected:** LLMOS/001 through LLMOS/013 (13 files)

### LLMOS — Uses banned `## Architecture` section
All 13 LLMOS files use `## Architecture` as a major section heading (violates Check #2).

### LLMOS — Non-standard document header
All 13 LLMOS files use `# AIOS Bible — Brain/LLMOS` instead of standard `# AIOS Bible — Brain`.

### LLMOS — Non-standard property table fields
All 13 LLMOS files have property table fields that differ from the standard 9-field table (e.g., include "Pipeline Stage" instead of "Source Physics").

---

## HIGH

### Sou/001–005 — Design DNA rule count: 5–7 (required: 11)
Standard files must list 11 Design DNA rules (R1–R6, R9, R10, R13, R15). Sou files list only 5–7:
| File | Rule count | Missing rules |
|------|-----------|---------------|
| Sou/001-Reasoning.md | 5 (R1, R5, R10, R12, R13) | R2, R3, R4, R6, R9, R14, R15 |
| Sou/002-Planner.md | 6 (R1, R4, R5, R10, R12, R13) | R2, R3, R6, R9, R14, R15 |
| Sou/003-Missions.md | 6 (R1, R3, R5, R10, R12, R13) | R2, R4, R6, R9, R14, R15 |
| Sou/004-Learning.md | 6 (R1, R3, R9, R10, R12, R13) | R2, R4, R5, R6, R14, R15 |
| Sou/005-Knowledge.md | 7 (R1, R3, R6, R10, R12, R13, R14) | R2, R4, R5, R9, R15 |

### Sou/001–005 — Design DNA uses wrong rule name format
Standard uses `R1 — Modulsingularity`, `R2 — Dependency Order`, etc. Sou files use different formats like `R1 (Modulsingularity)` with parentheses and inconsistent naming.

### Sou/001–005 — Events section uses bullet lists, not tables
All 5 Sou files use markdown bullet lists for Events instead of the standard pipe-table format with `| Event | Fields | Description |`.

### Sou/001–005 — Error Cases section uses bullet lists, not tables
All 5 Sou files use "Error Codes (R12)" with bullet lists instead of the standard `| Condition | Error Code | Behavior |` table.

### Sou/001–005 — No Invariants table with Enforcement column
All 5 Sou files lack a `## Invariants` section with the standard `| ID | Invariant | Enforcement |` three-column table.

### Sou/001–005 — Section numbering is non-standard
Sou files use `## Sou 001 — Reasoning` instead of the standard `## 001 — Name` format.

---

## MEDIUM

### Sou/001–005 — Section structure deviation
Sou files use non-standard sections (`Cross-Cutting Concerns`, `Edge Cases`, `Reasoning Methods`) instead of the standard `## Core Concepts` / `## Core Operations` / `## Internal Interface` pattern.

### Sou/001–005 — Internal Interface section missing in some files
- Sou/001-Reasoning.md: Has Internal Interface ✓
- Sou/002-Planner.md: Has Internal Interface ✓
- Sou/003-Missions.md: Has Internal Interface ✓
- Sou/004-Learning.md: Has Internal Interface ✓
- Sou/005-Knowledge.md: Has Internal Interface ✓

(All present, but structured differently from standard)

### Attention/001-Priority-Scoring.md — Uses `## Core Concepts` vs `## Core Operations`
Uses `## Core Concepts` heading while sibling file `002-Focus-Management.md` uses `## Core Operations`. Note: both are acceptable formats; inconsistency within directory.

### Memory/001–006 — No `## Core Concepts` or `## Core Operations` section
Memory files skip this section entirely, going directly from `## Data Model` to specialized sections like `## Slots` and `## CRUD Operations`.

---

## LOW

### Directory-specific Source Laws variation
Expected — different subsystems reference different constitutional laws. All directories show consistent internal patterns:
- Memory: Law 4 + Law 6 (or Law 5 for Semantic)
- Personality: Laws 1,3,4,5,6,7 — varies by component
- Planning: Laws 1,2,4,6
- Tools: Law 7 (Capability Bounds) — dominant
- Vision: Laws 3,4 throughout
- Voice: Laws 3,4 throughout
- Sou: Law 4 (Evidence) common to all

No inconsistencies flagged.

---

## INFO

### Line count ≥ 120 — PASS
All 67 non-Overview sub-doc files exceed 120 lines. Minimum observed: Sou/005-Knowledge.md (248 lines). Most are 300–500 lines.

### Property Table Fields — Standard (non-LLMOS, non-Sou)
All Memory (6), Personality (5), Planning (5), Tools (6), Vision (5), Voice (5), and some Brain-directory files use the standard 9-field table: Status, Version, Category, Document ID, Source Laws, Source Physics, Supersedes, Superseded By, Amended By.

Sou files (5) also use this standard property table.

### Events/Error Cases/Invariants/Related Documents tables — Standard directories
All Memory, Personality, Planning, Tools, Vision, Voice files use correct table formats:
- Events: `| Event | Fields | Description |`
- Error Cases: `| Condition | Error Code | Behavior |`
- Invariants: `| ID | Invariant | Enforcement |`
- Related Documents: `| Document | Relationship |`

### Related Documents table — Correct format in all standard files
All non-LLMOS, non-Sou files use `| Document | Relationship |` table format.

---

## Summary Statistics

| Severity | Count | Description |
|----------|-------|-------------|
| **Critical** | 4 categories | LLMOS: 13 files missing 5 sections each, banned Architecture heading, non-standard header, non-standard property table |
| **High** | 5 categories | Sou: Design DNA count/format wrong, Events/Error Cases/Invariants tables non-standard, section numbering non-standard |
| **Medium** | 3 categories | Sou section structure deviation, Attention section heading inconsistency, Memory missing Core Concepts section |
| **Low** | 1 category | Source Laws variation (expected) |
| **Info** | 5 categories | Line count pass, standard property tables, standard table formats, Related Documents format correct |

**Files requiring attention:** 13 LLMOS files (critical restructuring needed) + 5 Sou files (table format alignment needed) + 1 Attention file (naming inconsistency)
