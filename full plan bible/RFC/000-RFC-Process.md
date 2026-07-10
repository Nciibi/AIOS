# AIOS RFC Process
## 000 — How to Propose a Change

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | RFC |
| Document ID | RFC-PROCESS-000 |
| Source Laws | Law 4 — Evidence, Law 8 — Verification-First, Law 9 — Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The RFC (Request for Comments) process is how changes to AIOS are proposed, reviewed, approved, and implemented. Every change to the Bible, Constitution, Physics, or system architecture requires an RFC. This document is a practical step-by-step guide. For the complete specification, see `Bible/01-Governance/003-CRP.md`.

## When You Need an RFC

| Change Type | RFC Required? | Examples |
|-------------|---------------|----------|
| New Bible document | Yes | Adding a new specification |
| Bible document amendment | Yes | Changing an existing spec |
| Architecture decision | Yes | New service, interface change |
| Feature addition | Yes | New capability, new provider |
| Bug fix (spec deviation) | Yes | Fixing implementation to match spec |
| Constitutional amendment | Yes | Changing a Law |
| Typo/formatting fix | No — use PR directly | Spelling, formatting |
| Clarification (no semantic change) | No — use PR directly | Better wording, examples |
| Implementation detail (within spec) | No — use issue | Internal refactoring |

## Step-by-Step Process

### Step 1: Draft Your RFC

1. Copy `Templates/RFC-template.md` to a new file: `RFC-NNNN-Short-Name.md`
2. Replace the next available RFC number (start from `0001`)
3. Fill in all sections — Problem Statement, Proposed Solution, Impact Analysis, Evidence, Constitutional Review, Design DNA Compliance, Migration Plan
4. File goes in the `RFC/` directory (create a subdirectory like `0001-Short-Name/`)

### Step 2: Submit for Review

1. Create an RFC directory: `RFC/NNNN-Short-Name/`
2. Place your RFC file inside
3. Submit through the CRP by tagging the Security Council
4. Your RFC status changes to **Submitted** — it is now immutable
5. CRP assigns the RFC to the appropriate review queue

### Step 3: Review

| RFC Type | Review SLA | Approving Body |
|----------|-----------|----------------|
| Constitutional | 14 days | Sou (majority) + Security Council (unanimous) |
| Bible | 7 days | Security Council |
| Architecture | 7 days | Security Council + ADG |
| Feature | 7 days | Security Council |
| Bugfix | 24 hours (critical) / 7 days (standard) | Security Council |
| Clerical | 7 days | Security Council (simple majority) |

The Council may:
- **Approve**: RFC moves to Approved status
- **Request amendments**: RFC returns to Draft for revision
- **Reject**: RFC is closed with explanation

### Step 4: Implement

1. Once **Approved**, implementation begins
2. Implement the change in the relevant Bible document(s), code, or configuration
3. Reference the RFC number in all related commits
4. Run verification tests (unit, integration, contract)

### Step 5: Verification and Activation

1. Submit implementation for verification
2. Security Council verifies the implementation matches the RFC
3. If verification passes: status → **Verified** → **Active**
4. If verification fails: RFC returns to Draft with failure evidence

## RFC Checklist

### Before Submitting
- [ ] RFC number assigned and unique
- [ ] All sections filled (no TBD/TODO)
- [ ] Problem statement backed by evidence
- [ ] Proposed solution with alternatives considered (R10)
- [ ] Source Law(s) identified
- [ ] Design DNA compliance (R1–R15) assessed
- [ ] Impact analysis complete (documents, services, breaking changes)
- [ ] Migration plan included for breaking changes
- [ ] Author identity is a valid constitutional entity
- [ ] File named correctly: `RFC-NNNN-Short-Name.md`

### During Implementation
- [ ] RFC status → Approved before starting implementation
- [ ] All affected documents updated
- [ ] Tests added for new/changed behavior (R7)
- [ ] Error codes added for new failure modes (R12)
- [ ] Events documented for new state transitions
- [ ] Implementation referenced in commit messages

### Before Activation
- [ ] Implementation verified against RFC spec
- [ ] All tests pass
- [ ] Migration executed and verified (if breaking)
- [ ] Rollback plan exists and tested

## RFC Lifecycle Summary

```
Draft → Submitted → Review → Approved → Implemented → Verified → Active
                        → Rejected
                        → Draft (amendments requested)
                                     → Draft (verification failed)
           → Withdrawn (author withdraws)
```

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/01-Governance/003-CRP.md | Complete Change Request Pipeline specification |
| Bible/01-Governance/005-ADG.md | ADG process — architecture RFCs require ADG review |
| Bible/01-Governance/001-CLS.md | Constitutional amendments |
| Templates/RFC-template.md | RFC template — copy this to start a new RFC |
| Standards/002-BAS.md | Bible Authoring Standards — document format |
| Standards/003-DQC.md | Document Quality Checklist — quality criteria |
| Reference/002-Reference-Architecture.md | System architecture overview |
