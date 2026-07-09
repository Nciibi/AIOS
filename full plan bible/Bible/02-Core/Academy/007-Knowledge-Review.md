# AIOS Bible — Core
## Academy — 007: Knowledge Review

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-007 |
| Source Laws | Law 4 — Evidence, Law 2 — Autonomy |
| Source Physics | Physics/006-Lifecycles.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge Review process provides human or automated Engine oversight for knowledge artifacts that require it. While the Validator (005) and Verifier (006) are fully automated, Review adds a judgment layer for high-impact, novel, or ambiguous knowledge. Review ensures that the Academy's knowledge meets constitutional standards before becoming authoritative.

## When Review Is Required

Review is triggered automatically based on the following criteria:

| Criterion | Threshold | Knowledge Types Affected |
|-----------|-----------|-------------------------|
| **High impact** | Knowledge that could affect entity autonomy, security, or constitutional interpretation | Constitutional, Strategic |
| **Low confidence** | Verification confidence < threshold per type (see 006) | All types |
| **Novel domain** | Knowledge in a domain with no existing accepted artifacts | All types |
| **Contradiction** | Artifact contradicts accepted knowledge without clear supersede | All types |
| **Constitutional** | Any knowledge that interprets or extends constitutional meaning | Constitutional |
| **Human override** | Security Council explicitly requires review for an artifact | Any |

## Review Workflow

```
Pending → Assigned → Reviewing → Approved → Feedback
    │                            │
    └──→ Rejected ──────────────┘
```

| State | Description | Authorized Mutator |
|-------|-------------|-------------------|
| **Pending** | Artifact awaits reviewer assignment | Academy (auto) |
| **Assigned** | Reviewer has been assigned | Academy (auto) |
| **Reviewing** | Reviewer is actively evaluating the artifact | Reviewer |
| **Approved** | Artifact is approved for acceptance | Reviewer |
| **Rejected** | Artifact is rejected with feedback | Reviewer |
| **Feedback** | Reviewer provides actionable feedback for resubmission | Reviewer |

### Transition Matrix

| Transition | Authorized By | Condition |
|-----------|--------------|-----------|
| Pending → Assigned | Academy (auto) | Reviewer available within SLA |
| Assigned → Reviewing | Reviewer | Reviewer accepts assignment |
| Reviewing → Approved | Reviewer | Artifact meets review criteria |
| Reviewing → Rejected | Reviewer | Artifact fails review criteria |
| Reviewing → Feedback | Reviewer | Artifact requires revisions |
| Feedback → Pending | Source entity | Artifact resubmitted with revisions |

## Reviewer Assignment

Reviewer assignment follows the rules defined in Foundations/008-Object-Lifecycle.md (Reviewer Role section):

| Assignment Method | Description | When Used |
|-------------------|-------------|-----------|
| **By type** | Reviewer with domain expertise in the artifact's type | Default for all types |
| **By domain** | Reviewer with specific domain expertise | Domain, Strategic knowledge |
| **Random (bounded)** | Random selection from qualified reviewer pool | Low-risk operational knowledge |
| **Security Council** | Explicitly assigned by Security Council | Constitutional, high-impact |
| **Sou** | Explicitly assigned by Sou | Strategic, cross-domain |

### Reviewer Qualification

| Knowledge Type | Minimum Reviewer Qualification |
|----------------|-------------------------------|
| Operational | L2+ entity with domain experience |
| Domain | L3+ entity with domain expertise |
| Constitutional | Security Council member or delegate |
| Strategic | Sou or Security Council |
| Experimental | L2+ researcher entity with domain match |

### Reviewer Pool

The Academy maintains a pool of qualified reviewers. Reviewers are entities (human operators or automated review Engines) that have been granted the `knowledge.review` capability. The pool is managed by the Security Council.

| Pool Property | Description |
|---------------|-------------|
| Min reviewers per type | 3 (to ensure availability) |
| Max assignments per reviewer | 5 concurrent |
| Assignment timeout | 24 hours (automatic reassignment) |
| Reviewer exclusion | Reviewer cannot review their own proposed artifacts |

## Review SLA and Escalation

| Knowledge Type | Target SLA | Escalation Path |
|----------------|------------|-----------------|
| Operational | 4 hours | Reviewer pool → Supervisor → Security Council |
| Domain | 8 hours | Reviewer pool → Domain lead → Security Council |
| Constitutional | 24 hours | Security Council (no escalation beyond) |
| Strategic | 12 hours | Sou → Security Council |
| Experimental | 48 hours | Reviewer pool → Research lead |

### Escalation Process

```
SLA expires → Notify current reviewer
    │
    ▼
15 min → No response → Reassign to next available reviewer
    │
    ▼
2nd SLA expires → Notify reviewer supervisor
    │
    ▼
1 hour → No response → Escalate to Security Council
    │
    ▼
Security Council assigns reviewer or makes direct decision
```

## Review Criteria

The Reviewer evaluates the artifact against these criteria:

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Constitutional alignment | Critical | Does not violate any Law, Physics invariant, or Foundation |
| Evidence accuracy | High | Knowledge accurately represents source Events |
| Completeness | High | Knowledge provides sufficient context for its purpose |
| Clarity | Medium | Knowledge is clearly stated and unambiguous |
| Actionability | Medium | Knowledge can be acted upon by consumers |
| Novel value | Low | Knowledge adds new insight beyond existing artifacts |
| Reproducibility | High | Knowledge can be reproduced from source evidence (R9) |

### Review Decision

| Decision | Meaning | Next Step |
|----------|---------|-----------|
| **Approved** | Artifact meets all criteria | Proceed to Registry (004) |
| **Rejected** | Artifact fails critical criteria | Returned with rejection reason |
| **Feedback** | Artifact needs revisions | Returned to source entity with feedback |

## Review Artifact

Each review produces a structured review artifact:

| Field | Type | Description |
|-------|------|-------------|
| `review_id` | UUID | Review record identifier |
| `artifact_id` | UUID | The reviewed knowledge artifact |
| `reviewer_id` | UUID | Reviewer entity ID |
| `decision` | Enum | Approved, Rejected, Feedback |
| `score` | Float | Reviewer's overall score (0.0–1.0) |
| `criteria_scores` | JSON | Per-criterion scores |
| `comments` | String | Reviewer's comments and reasoning |
| `feedback_items` | FeedbackItem[] | Actionable feedback (for Feedback decision) |
| `timestamp` | DateTime | Review completion timestamp |

### FeedbackItem

| Field | Type | Description |
|-------|------|-------------|
| `field` | String | Artifact field requiring revision |
| `severity` | Enum | Critical, Major, Minor, Suggestion |
| `description` | String | What needs to change |
| `suggestion` | String | Suggested improvement |

## Review Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Review.ReviewRequired` | Artifact is flagged for review | artifact_id, reason, confidence_score |
| `Review.ReviewAssigned` | Reviewer is assigned | artifact_id, reviewer_id, sla_deadline |
| `Review.ReviewStarted` | Reviewer begins reviewing | artifact_id, reviewer_id |
| `Review.ReviewApproved` | Artifact is approved | artifact_id, reviewer_id, score |
| `Review.ReviewRejected` | Artifact is rejected | artifact_id, reviewer_id, reason |
| `Review.ReviewFeedback` | Artifact returned with feedback | artifact_id, reviewer_id, feedback_items |
| `Review.ReviewEscalated` | Review is escalated | artifact_id, reason, previous_reviewer |
| `Review.ReviewSLAExceeded` | SLA deadline passes | artifact_id, assigned_reviewer, elapsed_time |

## Cross-Cutting Concerns

### Security

Reviewers must be authenticated and authorized entities with the `knowledge.review` capability. Review decisions are cryptographically signed. The Security Council can override any review decision. Reviewers cannot review their own artifacts (separation of powers, GOV-005).

### Evidence

Every review action produces an Event. The complete review history of every artifact is auditable. Review decisions are evidence for the artifact's lifecycle transition.

### Lifecycle

Review is a conditional state in the AKM lifecycle: Validated → (Verified) → Review → Accepted. Not all artifacts require review; those that do cannot proceed to acceptance without an Approved decision.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| Assign review | `knowledge.review.assign` |
| Accept assignment | `knowledge.review` |
| Approve/Reject | `knowledge.review` |
| Provide feedback | `knowledge.review` |
| Escalate | `knowledge.review.escalate` |
| Override decision | `knowledge.review.override` (Security Council only) |

### Communication

The Review service subscribes to verification results via ACF topic `academy.knowledge.verified`. It publishes decisions to `academy.knowledge.reviewed` and `academy.knowledge.review_failed`. The Registry (004) subscribes to approved events.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Review does evaluation — does not store or distribute |
| R5 | All reviewer types implement the same Reviewer interface |
| R9 | Review assignment is deterministic (same criteria → same assignment) |
| R10 | Review workflow is linear and sequential |
| R12 | Every review error/exception has a unique code |
| R13 | Review fails closed if reviewer unavailable (escalation, not silent accept) |
| R14 | Paved path: Pending → Assigned → Reviewing → Approved/Rejected |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Governance/006-AKM.md | AKM defines when review is required |
| Foundations/008-Object-Lifecycle.md | Reviewer role definition, transition authorization |
| Foundations/001-AIOS-Philosophy.md | PHI-003 — graduated autonomy affects review requirements |
| Foundations/002-Design-DNA.md | R1, R5, R9, R10, R12, R13, R14 |
| Foundations/003-Core-Principles.md | GOV-005 — separation of powers in review |
| 005-Knowledge-Validator.md | Precedes Review in pipeline |
| 006-Knowledge-Verifier.md | Precedes Review (provides confidence score) |
| 004-Knowledge-Registry.md | Consumes review results for registration |
| 016-Knowledge-API.md | Review operations exposed through API |
