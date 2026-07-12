# Documentation Review Suggestions & Fix Log

Tracks cross-reference / semantic review passes over the AIOS Bible.
Harness scripts live in `%TEMP%\opencode\`: `verify_docs.ps1`, `recheck.ps1`, `eventcheck.ps1`, `semcheck.ps1`, `tracecheck.ps1`.

## Final Harness State (last run)
- `verify_docs.ps1`: **FAIL=0 WARN=0** (175 files)
- `recheck.ps1`: 0 broken inline / 0 empty sections (6 incidental "placeholder" word hits in legitimate UI/scratch-space prose) / 0 undefined events / 0 out-of-range Law
- `semcheck.ps1`: 0 foundation invariant out-of-range / 0 unresolved Physics invariant refs / 0 Design DNA rule out-of-range

## S1–S5 (prior passes)
- S3 event traceability: 1269 events, 1230 "orphans" = expected runtime-consumption noise, non-actionable.
- S5 semantic checks: invariant/rule refs within range.
- P3 forward-refs cleared: created `04-Execution/Security/ATS/000-Overview.md`; repointed 24 dir refs to `.md`; `Risk → 000-RE.md`.

## S6 — Broken Cross-Reference Repair Pass (current)
Systematic wrong-path references the verifier's Related-Documents-only check missed. Confirmed targets before editing.

### Fixes applied
| File | Wrong ref | Correct target |
|------|-----------|----------------|
| `02-Core/Agents/001-Factory.md` | `Bible/02-Core/IDS/000-Overview.md` | `Bible/04-Execution/Security/IDS/000-Overview.md` |
| `02-Core/Agents/001-Factory.md` | `Bible/02-Core/SSM/000-Overview.md` | `Bible/04-Execution/Security/SSM/000-SSM.md` |
| `02-Core/Agents/002-Templates.md` | `Bible/02-Core/SSM/000-Overview.md` | `Bible/04-Execution/Security/SSM/000-SSM.md` |
| `02-Core/Agents/003-Configuration.md` | `Bible/02-Core/SSM/...` , `Bible/02-Core/IDS/...` | Security/SSM/000-SSM.md , Security/IDS/000-Overview.md |
| `02-Core/Agents/004-Lifecycle.md` | `Bible/02-Core/IDS/...` , `Bible/02-Core/SSM/...` | Security/IDS , Security/SSM/000-SSM.md |
| `02-Core/Agents/004-Lifecycle.md` | `Bible/03-Institutions/ROS/000-Overview.md` | `Bible/02-Core/ROS/000-Overview.md` |
| `02-Core/Agents/004-Lifecycle.md` | `Bible/03-Institutions/Works/000-Overview.md` | `Bible/03-Institutions/Workers/000-Overview.md` |
| `04-Execution/Runtime/002-Claude.md` | `Bible/04-Execution/LLMOS/` (prose + 2 related-doc lines) | `Bible/02-Core/Brain/LLMOS/` |
| `04-Execution/Runtime/004-Ollama.md` | `Bible/04-Execution/LLMOS/` | `Bible/02-Core/Brain/LLMOS/` |
| `05-Platform/009-TP.md` | `Core/AGS/000-Overview.md` | `Bible/02-Core/AGS/000-Overview.md` |
| `05-Platform/009-TP.md` | `04-Execution/Security/IDS/000-IDS.md` | `04-Execution/Security/IDS/000-Overview.md` |
| `05-Platform/009-TP.md` | `04-Execution/Resources/ROS/000-ROS.md` | `Bible/02-Core/ROS/000-Overview.md` |
| `06-Services/Cryptography/SMS/000-SMS.md` | `04-Execution/Security/IDS/000-IDS.md` | `04-Execution/Security/IDS/000-Overview.md` |
| `04-Execution/Security/Verification/007-Risk-Stage.md` | `Bible/04-Execution/Security/Security-Council/000-Overview.md` | `Bible/04-Execution/Security/000-Overview.md` |
| `04-Execution/Security/Verification/008-Authorization-Stage.md` | `.../Security-Council/000-Overview.md` | `Bible/04-Execution/Security/000-Overview.md` |

### Intentionally left as-is (not defects)
- `0010-Brain-Restructuring-Plan.md:83,214` — historical move record (LLMOS moved `04-Execution/LLMOS/` → `02-Core/Brain/LLMOS/`).
- `02-Core/Brain/LLMOS/000-Overview.md:12` — `Supersedes` metadata pointer to its prior location.
- `Bible/02-Core/AGS/000-Overview.md` (many files) — AGS genuinely lives under `02-Core/AGS/`; valid.

## Deferred (architectural "Needs Discussion")
- Law 0 "Law of Layering" convention (`00-Foundations/009-Versioning.md`, `004-System-Layers.md`).
- EAS acronym collision (Execution-Auth vs Execution Engine).
- IRS/IDS naming consistency.
- Physics docs at repo root vs under `02-Core/`.
