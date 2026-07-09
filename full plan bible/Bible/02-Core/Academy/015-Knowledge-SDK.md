# AIOS Bible — Core
## Academy — 015: Knowledge SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-015 |
| Source Laws | Law 4 — Evidence, Law 1 — Identity |
| Source Physics | Physics/009-Interaction.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge SDK provides a first-class developer experience for building knowledge-aware tools and applications on top of the Academy. It wraps the Knowledge API (016) in idiomatic TypeScript (primary) and Rust (bindings), handling authentication, serialization, error handling, and event consumption so that developers can focus on knowledge-driven logic.

All SDK communication flows through ACF (Physics/009-Interaction.md). Every SDK operation requires a valid entity identity and appropriate authorization.

## SDK Capabilities

| Capability | TypeScript | Rust | Description |
|------------|------------|------|-------------|
| Query Academy | ✅ | ✅ | Search and query knowledge artifacts |
| Submit knowledge | ✅ | ✅ | Propose new knowledge for validation |
| Consume knowledge events | ✅ | ✅ | Subscribe to knowledge lifecycle events |
| Knowledge-driven interfaces | ✅ | 🔜 | Build interfaces that adapt to knowledge |
| Provenance verification | ✅ | ✅ | Verify knowledge provenance chains |
| Knowledge composition | ✅ | ✅ | Request KCE composition operations |
| Execution requests | ✅ | ✅ | Request KEE execution of knowledge |

## SDK Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Application Code                           │
│  (Uses SDK to interact with Academy)                        │
└────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│  Knowledge SDK                                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │  Auth       │  │  Query     │  │  Event Consumer    │   │
│  │  Module     │  │  Module    │  │  Module            │   │
│  └────────────┘  └────────────┘  └────────────────────┘   │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │  Submit     │  │  Compose   │  │  Execute           │   │
│  │  Module     │  │  Module    │  │  Module            │   │
│  └────────────┘  └────────────┘  └────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ACF Transport Layer (all communication via ACF)    │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
                         │
                         ▼
                    ACF Network
                         │
                         ▼
                    Academy Services
```

## SDK Module Reference

### Auth Module

Handles entity identity and authentication for all SDK operations.

| Method | Description |
|--------|-------------|
| `authenticate(entity_id, credentials)` | Authenticate with ATS and obtain session token |
| `setIdentity(identity)` | Set identity for subsequent operations |
| `getCurrentEntity()` | Returns authenticated entity info |
| `hasCapability(capability)` | Check if entity has a specific capability |

```typescript
// TypeScript example
const sdk = new KnowledgeSDK();
await sdk.authenticate('AG-042', { apiKey: 'sk-...' });
```

### Query Module

Query and search knowledge artifacts from the Academy.

| Method | Description | Equivalent API (016) |
|--------|-------------|---------------------|
| `search(query, options)` | Full-text and semantic search | `searchKnowledge` |
| `getKnowledge(id)` | Retrieve artifact by ID | `getKnowledge` |
| `listKnowledge(filters)` | List artifacts matching filters | `listKnowledge` |
| `getProvenance(id, options)` | Get provenance chain | `getProvenance` |
| `queryGraph(query)` | Graph traversal query | `queryKnowledge` (graph type) |

### Event Consumer Module

Subscribe to and consume knowledge lifecycle events.

| Method | Description |
|--------|-------------|
| `subscribe(topic, callback)` | Subscribe to knowledge events |
| `unsubscribe(subscriptionId)` | Unsubscribe from events |
| `onKnowledgeAccepted(callback)` | Convenience: subscribe to accepted events |
| `onKnowledgeDeprecated(callback)` | Convenience: subscribe to deprecation events |

```typescript
// TypeScript example
sdk.onKnowledgeAccepted((event) => {
    console.log(`New knowledge: ${event.artifact_id}`);
    const artifact = await sdk.getKnowledge(event.artifact_id);
    // Process artifact
});
```

### Submit Module

Propose new knowledge artifacts to the Academy.

| Method | Description |
|--------|-------------|
| `proposeKnowledge(artifact)` | Submit knowledge for validation |
| `getProposalStatus(proposalId)` | Check status of submitted proposal |
| `withdrawProposal(proposalId)` | Withdraw a pending proposal |
| `resubmitKnowledge(proposalId, updatedArtifact)` | Resubmit with revisions |

```typescript
// TypeScript example
const proposal = await sdk.proposeKnowledge({
    type: 'operational',
    title: 'JWT Authentication Procedure',
    content: { steps: [...] },
    sourceEventIds: ['E-001', 'E-002']
});
// proposal.status === 'Proposed'
```

### Compose Module

Request KCE composition operations.

| Method | Description |
|--------|-------------|
| `composeUnion(artifactIds)` | Union composition |
| `composeIntersection(artifactIds)` | Intersection composition |
| `composeAnalogy(sourceId, targetDomain)` | Analogy composition |
| `composeInduction(artifactIds)` | Induction composition |
| `composeDeduction(principleId, context)` | Deduction composition |
| `getCompositionStatus(requestId)` | Check composition request status |

### Execute Module

Request KEE execution of knowledge artifacts.

| Method | Description |
|--------|-------------|
| `executeKnowledge(knowledgeId, context)` | Execute a knowledge artifact |
| `getExecutionStatus(executionId)` | Check execution status |
| `cancelExecution(executionId)` | Cancel a pending execution |
| `getExecutionResult(executionId)` | Get execution result |

## Authentication and Authorization

All SDK operations require authentication:

| Step | Description |
|------|-------------|
| 1 | Entity authenticates via SDK `authenticate()` method |
| 2 | SDK obtains session token from ATS |
| 3 | SDK includes token in all ACF requests |
| 4 | ACF validates token and checks authorization |
| 5 | Unauthorized requests return error with code |

```typescript
// All SDK methods automatically handle auth
try {
    const results = await sdk.search('authentication');
} catch (error) {
    if (error.code === 'AUTH_001') {
        // Re-authenticate
    }
    if (error.code === 'AUTHZ_001') {
        // Entity lacks capability
    }
}
```

## Error Handling

SDK provides typed errors matching the Academy error codes (R12):

| Error Category | Prefix | Example |
|----------------|--------|---------|
| Authentication | `AUTH_*` | `AUTH_001` — Invalid credentials |
| Authorization | `AUTHZ_*` | `AUTHZ_003` — Insufficient capabilities |
| Validation | `VAL_*` | `VAL.SCHEMA_001` — Invalid artifact type |
| Verification | `VER_*` | `VER.CONF_001` — Below confidence threshold |
| Not found | `NOT_FOUND_*` | `NOT_FOUND_001` — Artifact not found |
| Rate limit | `RATE_*` | `RATE_001` — Too many requests |
| Timeout | `TIMEOUT_*` | `TIMEOUT_001` — Request timed out |

## SDK Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `SDK.Authenticated` | SDK successfully authenticates | entity_id, session_token_expiry |
| `SDK.QueryExecuted` | SDK executes a query | method, filter_count, result_count |
| `SDK.KnowledgeProposed` | SDK proposes knowledge | artifact_id, proposal_id |
| `SDK.EventSubscribed` | SDK subscribes to a topic | topic, subscription_id |
| `SDK.EventReceived` | SDK receives an event | topic, event_type, artifact_id |
| `SDK.ErrorEncountered` | SDK encounters an error | error_code, context |

## Cross-Cutting Concerns

### Security

All SDK communication is authenticated and authorized through ACF. The SDK never stores credentials in plaintext. Session tokens are managed securely (memory-only, never logged). The SDK validates server responses (checks signatures where applicable).

### Evidence

SDK operations produce Events on the server side (Academy Events). The SDK does not produce Events itself — it triggers server-side Event production through API calls and subscriptions.

### Lifecycle

The SDK is stateless from the Academy's perspective. It authenticates per-session and maintains no persistent state. Applications built on the SDK may have their own lifecycle management.

### Capability Bounds

The SDK enforces capability checks at the client side (fast-fail) but relies on server-side enforcement for authorization:

| Operation | Client Check | Server Enforcement |
|-----------|-------------|-------------------|
| Query | Token present | `knowledge.query` capability |
| Propose | Token present | `knowledge.propose` capability |
| Execute | Token present | `knowledge.execute` capability |
| Compose | Token present | `knowledge.compose` capability |
| Subscribe | Token present | `knowledge.subscribe` capability |

### Communication

All SDK communication flows through ACF (Physics/009-Interaction.md). The SDK uses ACF request-response for queries and ACF pub-sub for event consumption. No direct connections to Academy services bypass ACF.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | SDK does interface — does not implement Academy logic |
| R6 | SDK receives ACF transport through dependency injection |
| R9 | All SDK methods are deterministic (same params → same ACF message) |
| R12 | SDK uses typed errors matching Academy error codes |
| R13 | SDK fails closed (no silent failures) |
| R14 | Paved path: authenticate → query/submit → handle response |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/009-Interaction.md | SDK communicates via ACF |
| Governance/006-AKM.md | SDK enables developers to interact with AKM-governed knowledge |
| Foundations/001-AIOS-Philosophy.md | PHI-004 — Identity Precedes Action (all SDK ops require identity) |
| Foundations/002-Design-DNA.md | R1, R6, R9, R12, R13, R14 |
| Foundations/003-Core-Principles.md | CPR-005 — Verify Every Action (SDK requests verified server-side) |
| 016-Knowledge-API.md | SDK wraps all API operations |
| 005-Knowledge-Validator.md | SDK submit module interacts with validation |
| 013-KEE.md | SDK execute module interacts with KEE |
| 014-KCE.md | SDK compose module interacts with KCE |
| 010-Knowledge-Search.md | SDK query module interacts with search |
