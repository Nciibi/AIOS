# AIOS Bible — Core
## Academy — 016: Knowledge API

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-016 |
| Source Laws | Law 4 — Evidence, Law 1 — Identity |
| Source Physics | Physics/009-Interaction.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge API is the complete external interface to the Academy. All Academy operations — querying, proposing, validating, composing, executing, and subscribing to knowledge — are exposed through this API over ACF. The Knowledge SDK (015) wraps this API for developer convenience; direct API access is available for advanced use cases and for non-TypeScript/Rust consumers.

## API Conventions

### Transport

All API operations use ACF (Application Communication Framework):

| Aspect | Specification |
|--------|---------------|
| Transport | ACF message-based (request-response, pub-sub) |
| Serialization | JSON (UTF-8) |
| Authentication | ACF-level (entity identity + session token) |
| Authorization | ACF-level (capability check) |
| Idempotency | Supported via `idempotency_key` header |

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Entity-ID` | Yes | Authenticated entity ID |
| `X-Session-Token` | Yes | Session token from ATS |
| `X-Idempotency-Key` | No | Idempotency key for mutation operations |
| `X-Request-ID` | No | Client-generated request ID (for tracing) |

### Response Format

All responses follow a standard envelope:

```json
{
    "success": true,
    "data": { ... },
    "meta": {
        "request_id": "req-001",
        "timestamp": "2026-07-09T12:00:00Z",
        "latency_ms": 42
    }
}
```

Error responses:

```json
{
    "success": false,
    "error": {
        "code": "VAL.SCHEMA_001",
        "message": "Invalid artifact type",
        "field": "type",
        "request_id": "req-001"
    }
}
```

### Rate Limiting

| Limit | Default | Burst |
|-------|---------|-------|
| Queries per second | 100 | 200 |
| Mutations per second | 20 | 40 |
| Event subscriptions per entity | 10 | — |

Rate limit exceeded responses return error code `RATE_001`.

### Pagination

List operations support pagination:

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `page` | 1 | 10000 | Page number (1-indexed) |
| `page_size` | 20 | 100 | Items per page |
| `sort_by` | `accepted_at` | — | Sort field |
| `sort_order` | `desc` | — | Sort direction |

### Filtering

List and query operations support filters:

| Filter syntax | Example | Description |
|---------------|---------|-------------|
| `type=operational` | Exact match | Filter by knowledge type |
| `tags=deployment,security` | AND match | Filter by tags |
| `confidence_min=0.7` | Range min | Minimum confidence |
| `created_after=2026-01-01T00:00:00Z` | Range start | Created after timestamp |

## API Operations

### createKnowledge

Propose a new knowledge artifact.

| Endpoint | `academy.knowledge.create` |
|----------|---------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.propose` |

**Request**:
```json
{
    "type": "operational",
    "title": "JWT Authentication Procedure",
    "description": "Step-by-step procedure for JWT authentication",
    "content": { "steps": [...] },
    "source_event_ids": ["E-001", "E-002"],
    "metadata": { "domain": "security", "tags": ["auth", "jwt"] }
}
```

**Response**: `{ artifact_id, version: "1.0.0", status: "Generated" }`

**Error Codes**: `VAL.SCHEMA_001-006`, `AUTHZ_003`

### validateKnowledge

Trigger validation (typically automatic, but available for manual re-validation).

| Endpoint | `academy.knowledge.validate` |
|----------|------------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.validate` |

**Request**: `{ artifact_id }`

**Response**: `{ artifact_id, passed, score, stage_results }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`

### acceptKnowledge

Accept a validated and verified knowledge artifact into the Registry.

| Endpoint | `academy.knowledge.accept` |
|----------|---------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.accept` |

**Request**: `{ artifact_id, validation_proof, review_proof (if required) }`

**Response**: `{ registry_id, status: "Registered", accepted_at }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`, `VAL.CONST_001-005`

### queryKnowledge

Query knowledge artifacts by graph traversal or structured filters.

| Endpoint | `academy.knowledge.query` |
|----------|---------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.query` |

**Request**:
```json
{
    "query_type": "graph",
    "start_node_id": "A-001",
    "edge_types": ["derived_from", "supports"],
    "max_depth": 3,
    "filters": { "type": "operational" }
}
```

**Response**: `{ results: [{ node_id, type, title, score }], total_count }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`

### searchKnowledge

Full-text, semantic, or faceted search across knowledge artifacts.

| Endpoint | `academy.knowledge.search` |
|----------|---------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.query` |

**Request**:
```json
{
    "q": "JWT authentication",
    "search_type": "fulltext",
    "fields": ["title", "description"],
    "filters": { "type": "operational", "confidence_min": 0.7 },
    "page": 1,
    "page_size": 20
}
```

**Response**: `{ results: [{ id, type, title, score, highlights }], total_count, page }`

**Error Codes**: `AUTHZ_003`, `RATE_001`

### getKnowledge

Retrieve a specific knowledge artifact by ID.

| Endpoint | `academy.knowledge.get` |
|----------|------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.query` |

**Request**: `{ artifact_id, version (optional), include_deprecated (optional) }`

**Response**: `{ id, type, title, description, content, version, status, confidence, organization_id, accepted_at, ... }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`

### getProvenance

Get the full provenance chain for an artifact.

| Endpoint | `academy.knowledge.provenance` |
|----------|-------------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.query` |

**Request**: `{ artifact_id, depth (optional), verify (optional) }`

**Response**: `{ artifact_id, chain: [...], source_events: [...], verified }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`

### listKnowledge

List knowledge artifacts with filters and pagination.

| Endpoint | `academy.knowledge.list` |
|----------|-------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.query` |

**Request**:
```json
{
    "filters": { "type": "operational", "organization_id": "ORG-001" },
    "page": 1,
    "page_size": 20,
    "sort_by": "accepted_at",
    "sort_order": "desc"
}
```

**Response**: `{ entries: [...], total_count, page, page_size }`

**Error Codes**: `AUTHZ_003`

### deprecateKnowledge

Deprecate a knowledge artifact.

| Endpoint | `academy.knowledge.deprecate` |
|----------|------------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.deprecate` |

**Request**: `{ artifact_id, reason, superseded_by (optional) }`

**Response**: `{ artifact_id, status: "Deprecated", superseded_by }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`

### subscribeKnowledge

Subscribe to knowledge lifecycle events.

| Endpoint | `academy.knowledge.subscribe` |
|----------|------------------------------|
| Method | ACF Pub-Sub |
| Authorization | `knowledge.subscribe` |

**Request**: `{ topic_pattern, entity_id, callback_endpoint }`

Topic patterns:
- `knowledge.published.{org_id}` — All knowledge in an org
- `knowledge.published.{org_id}.{type}` — Knowledge by type in org
- `knowledge.published.global.*` — Global knowledge
- `knowledge.lifecycle.*` — All lifecycle events

**Response**: `{ subscription_id, topic, created_at }`

**Error Codes**: `AUTHZ_003`, `RATE_001`

### composeKnowledge

Request KCE knowledge composition.

| Endpoint | `academy.knowledge.compose` |
|----------|-----------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.compose.{method}` |

**Request**:
```json
{
    "method": "analogy",
    "source_artifact_ids": ["A-001"],
    "target_domain": "privacy",
    "parameters": {}
}
```

**Response**: `{ request_id, status: "Processing", composed_artifact_id (if synchronous) }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`, `KCE.COMP_001`

### executeKnowledge

Request KEE knowledge execution.

| Endpoint | `academy.knowledge.execute` |
|----------|----------------------------|
| Method | ACF Request-Response |
| Authorization | `knowledge.execute.{type}` |

**Request**: `{ knowledge_id, context: {...}, mission_id (optional) }`

**Response**: `{ execution_id, status: "Planned", plan_summary }`

**Error Codes**: `NOT_FOUND_001`, `AUTHZ_003`, `KEE.EXEC_001`

## API Operations Summary

| Operation | Endpoint | Method | Mutation | Authorization |
|-----------|----------|--------|----------|---------------|
| createKnowledge | `academy.knowledge.create` | Request-Response | Yes | `knowledge.propose` |
| validateKnowledge | `academy.knowledge.validate` | Request-Response | No | `knowledge.validate` |
| acceptKnowledge | `academy.knowledge.accept` | Request-Response | Yes | `knowledge.accept` |
| queryKnowledge | `academy.knowledge.query` | Request-Response | No | `knowledge.query` |
| searchKnowledge | `academy.knowledge.search` | Request-Response | No | `knowledge.query` |
| getKnowledge | `academy.knowledge.get` | Request-Response | No | `knowledge.query` |
| getProvenance | `academy.knowledge.provenance` | Request-Response | No | `knowledge.query` |
| listKnowledge | `academy.knowledge.list` | Request-Response | No | `knowledge.query` |
| deprecateKnowledge | `academy.knowledge.deprecate` | Request-Response | Yes | `knowledge.deprecate` |
| subscribeKnowledge | `academy.knowledge.subscribe` | Pub-Sub | Yes | `knowledge.subscribe` |
| composeKnowledge | `academy.knowledge.compose` | Request-Response | Yes | `knowledge.compose.{method}` |
| executeKnowledge | `academy.knowledge.execute` | Request-Response | Yes | `knowledge.execute.{type}` |

## API Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `API.RequestReceived` | API receives a request | endpoint, entity_id, request_id |
| `API.RequestCompleted` | API completes processing | endpoint, entity_id, latency_ms, success |
| `API.RequestFailed` | API encounters an error | endpoint, error_code, request_id |
| `API.RateLimitExceeded` | Rate limit is exceeded | entity_id, limit_type, retry_after |
| `API.SubscriptionCreated` | Subscription created | subscription_id, topic, entity_id |
| `API.SubscriptionRemoved` | Subscription removed | subscription_id, reason |

## Cross-Cutting Concerns

### Security

Every API request is authenticated (entity identity + session token from ATS). Authorization is checked per-operation (capability-based). Idempotency keys prevent duplicate mutations. Rate limiting prevents abuse (Physics/008-Security.md).

### Evidence

Every API operation produces an Event (request received, completed, or failed). API logs are derived from these Events, not from separate logging. The full request history is reconstructable.

### Lifecycle

The API is stateless — it does not maintain session state beyond ACF-level authentication. All state is managed by the underlying Academy services. API operations follow the lifecycle of the artifacts they operate on.

### Capability Bounds

API operations are capability-bounded (see Authorization column above). Capabilities are scoped by organization, knowledge type, and autonomy level. The API does not bypass capability enforcement.

### Communication

All API operations go through ACF (Physics/009-Interaction.md). The API is the single external-facing interface for the Academy — no direct access to internal Academy services is permitted. The SDK (015) wraps this API.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | API does interface — does not implement Academy logic |
| R3 | API is the single interface for all Academy operations |
| R6 | API receives ACF transport through dependency injection |
| R9 | API operations are deterministic (same input → same output) |
| R10 | API uses simple request-response pattern with consistent envelope |
| R12 | Every error has a unique code |
| R13 | API fails closed on internal service failure |
| R14 | Paved path: authenticate → authorize → execute → respond |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/009-Interaction.md | ACF transport conventions |
| Physics/008-Security.md | API security, rate limiting, auth |
| Governance/006-AKM.md | API exposes AKM-governed operations |
| Foundations/001-AIOS-Philosophy.md | PHI-004 — identity required for all API access |
| Foundations/002-Design-DNA.md | R1, R3, R6, R9, R10, R12, R13, R14 |
| Foundations/003-Core-Principles.md | CPR-005 — Verify Every Action |
| 002-KMS.md | API wraps KMS operations |
| 004-Knowledge-Registry.md | API wraps Registry operations |
| 005-Knowledge-Validator.md | API wraps validation |
| 006-Knowledge-Verifier.md | API wraps verification |
| 007-Knowledge-Review.md | API wraps review |
| 009-Knowledge-Distribution.md | API wraps distribution |
| 010-Knowledge-Search.md | API wraps search |
| 011-Knowledge-Provenance.md | API wraps provenance |
| 013-KEE.md | API wraps KEE execution |
| 014-KCE.md | API wraps KCE composition |
| 015-Knowledge-SDK.md | SDK wraps this API |
