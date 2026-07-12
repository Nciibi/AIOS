# Cross-Reference Audit: Broken Links in Brain Docs

## Summary
- **Total unique references found**: 139
- **Broken references**: 14 (10.1%)
- **Files affected**: 20 source locations across 14 Brain sub-docs
- **Audit scope**: All 92 `.md` files under `Bible/02-Core/Brain/`

---

## 1. `Bible/03-Institutions/000-Overview.md` — File does not exist
`Bible/03-Institutions/` contains only subdirectories (Missions, Organizations, Workers), no overview file.
- `Brain/000-Overview.md:202`
- `Sou/000-Overview.md:162`

## 2. `Bible/02-Core/Physics/009-Interaction.md` — Wrong path prefix
Physics files live at `Physics/` root, not under `Bible/02-Core/Physics/`. Correct: `Physics/009-Interaction.md`.
- `Conversation/001-Dialogue-State.md:727`

## 3. `Bible/04-Execution/LLMOS/000-Overview.md` — Moved location (intentional)
LLMOS was moved from `Bible/04-Execution/LLMOS/` to `Bible/02-Core/Brain/LLMOS/`. This ref appears only in the Supersedes field — knowingly broken.
- `LLMOS/000-Overview.md:12` (Supersedes property)

## 4. `Bible/04-Execution/Security/PIP/000-PIP.md` — No PIP subdirectory
`Bible/04-Execution/Security/` has no PIP subdirectory. Did it get renamed or never created?
- `Autonomy/002-ACE.md:425`

## 5. `Bible/05-Platform/005-Sessions.md` — Wrong filename
Platform files are 000-LMS.md through 013-Graph-Framework.md. No `005-Sessions.md`. Might have been renamed to `005-AUS.md`.
- `Voice/004-Streaming.md:389`
- `Voice/005-Emotion-Detection.md:361`

## 6. `Bible/05-Platform/007-Config.md` — Wrong filename
Platform file 007 is `007-EIP.md`, not `007-Config.md`.
- `Decision/002-Trade-off-Analysis.md:611`

## 7. `Bible/05-Platform/ROS/000-Overview.md` — Wrong directory
ROS is at `Bible/02-Core/ROS/`, not under `Bible/05-Platform/`.
- `LLMOS/005-Memory-Injection.md:160`
- `LLMOS/006-Token-Budget-Manager.md:151`
- `LLMOS/007-Cost-Optimizer.md:140`

## 8. `Bible/06-Governance/001-Security-Council.md` — Directory doesn't exist
`Bible/06-Governance/` appears to be empty or non-existent. Security Council docs might be elsewhere.
- `Personality/001-Identity-Profile.md:267`
- `Personality/005-Evolution.md:428`

## 9. `Brain/Physics/006-Lifecycles.md` — No Physics subdirectory under Brain
Physics docs are at `Physics/` root. Correct: `Physics/006-Lifecycles.md`.
- `Tools/006-Lifecycle.md:422`

## 10. `Physics/008-Decision.md` — No such Physics file
Physics has `008-Security.md`, not `008-Decision.md`. This file may need to be created or the reference is to a non-existent file.
- `Personality/002-Values.md:11` (Source Physics property)

## 11. `Physics/008-Verification.md` — No such Physics file
Referenced as Source Physics; no matching file on disk.
- `LLMOS/010-Guardrails.md:217`

## 12. `Physics/009-Causality.md` — No such Physics file
Referenced in Source Physics of 3 Cognitive docs. Physics has `009-Interaction.md`, not Causality.
- `Cognitive/003-Metacognition.md:11`
- `Cognitive/004-Cognitive-Biases.md:11`
- `Cognitive/005-Confidence.md:11`

## 13. `Physics/011-Balance.md` — No such Physics file
Referenced in Source Physics of 2 Context docs. Physics has `011-Design-DNA.md`.
- `Context/003-Compression-Engine.md:11`
- `Context/004-TTL-Eviction.md:11`

## 14. `Bible/01-Bible/01-Governance/002-DGP.md` — Double `Bible/` prefix
Actual file is at `Bible/01-Governance/002-DGP.md` (no extra `Bible/` segment).
- `Sou/001-Reasoning.md:269`
