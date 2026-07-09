# AIOS Bible — Identity Service (IDS)
## 005 — Identity Provenance

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Identity |
| Document ID | AIOS-BIBLE-IDS-005 |
| Source Laws | Law/5 — Law of Identity, Law/8 — Law of Verification-First |
| Source Physics | Physics/001-Identity.md |

## Purpose

Identity Provenance tracks the authority chain for every identity operation. Every identity exists because some entity created it. Every identity changes state because some entity authorized it. Provenance answers: *who authorized this identity's existence and lifecycle transitions?*

## Provenance Chain Structure

Every identity record embeds a `provenance` field of type `ProvenanceChain`:

```typescript
interface ProvenanceChain {
  created_by: string;        // Identity ID of the creator entity
  authorized_by: string;     // Identity ID of the authorizing entity (may differ from creator)
  creation_request: {        // The original creation request
    entity_type: string;
    entity_id: string;
    metadata: object;
  };
  authorization_signature: string;  // Signature of the authorizing entity
  lifecycle_events: [{       // All lifecycle transitions with provenance
    transition: string;      // e.g., "created → verified"
    authorized_by: string;  // Identity ID of the authorizing entity
    timestamp: number;
    reason: string;
    event_id: string;       // Reference to the Event in Event Store
  }];
}
```

## Provenance Verification

### At Creation

When an identity is created, the Identity Factory verifies:
1. The requesting entity is authenticated (valid token)
2. The requesting entity has authority to create identities of this type
3. The creation request is signed by the authorizing entity

### At Lifecycle Transitions

Every lifecycle transition records:
- Which entity authorized the transition
- The authorization token or evidence
- The reason for the transition
- A link to the corresponding Event in the Event Store

### At Verification Pipeline

The Security Council's Stage 1 (Identity Verification) checks:
1. Identity exists
2. Identity is Active
3. Identity signature is valid
4. Entity binding matches the requesting entity
5. Provenance chain is intact (no broken links)

## Audit Trail

IDS produces an audit record for every identity operation:

- Identity ID
- Operation (create, verify, activate, suspend, restore, retire, archive)
- Timestamp (monotonic)
- Requesting entity (identity of the requester)
- Authorization token (from the Security Council, if applicable)
- Previous status and new status
- Reason (for state changes)

Audit records are Events stored in the Event Store. They are immutable and accessible through:
- Event Store API (for programmatic access)
- IDS query interface (for identity-specific audit)
- Security Council console (for security investigations)

## Future Work: External Federated Provenance

When IDs are federated across AIOS instances, the provenance chain must be verified across instance boundaries. This requires:
- Trust anchors between IDS instances
- Signed provenance assertions that can be verified by a third party
- Cross-instance audit trail linking (future enhancement)