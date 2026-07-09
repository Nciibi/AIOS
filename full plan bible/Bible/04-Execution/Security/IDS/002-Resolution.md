# AIOS Bible — Identity Service (IDS)
## 002 — Identity Resolution

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Identity |
| Document ID | AIOS-BIBLE-IDS-002 |
| Source Laws | Law 5 — Law of Identity |
| Source Physics | Physics/001-Identity.md |

## Purpose

Identity Resolution is the query interface to the IDS Registry. It allows any constitutional entity to look up identity records by identity_id or by entity binding. Resolution is the primary mechanism through which the Security Council, ACF, and Runtime Engines verify identity during the verification pipeline.

## Resolution Operations

### resolveIdentity(identity_id)

Resolve an identity to its current record.

**Authorization**: Any entity may query identity resolution. Resolution queries are logged.

**Process**:
1. Load identity record from Registry Store
2. If status is `Archived`, return archived record with `status: "archived"` marker
3. Return identity record with current status

### resolveEntityIdentity(entity_type, entity_id)

Resolve an entity's identity by its entity ID.

**Authorization**: Same as resolveIdentity — open to all constitutional entities.

**Process**:
1. Query Registry Store for identities matching `entity_type` and `entity_id`
2. Return identity record(s) — must be exactly one (Invariant: One Identity Per Entity)

## Pipeline Integration

Identity resolution is the first stage of the Security Council's verification pipeline. The Security Council calls `resolveIdentity` on every action request. The verification checks:

| Check | Condition | Failure Action |
|-------|-----------|---------------|
| Identity exists | `resolveIdentity` returns a record | Deny action, log as security event |
| Identity is active | `status == Active` | Deny action, log as security event |
| Identity is authentic | Cryptographic signature matches | Deny action, escalate as identity spoofing |
| Entity binding matches | `entity_id` matches the requesting entity | Deny action, log as security event |

The verification result is cached for the identity's verification TTL (default: 60 seconds, configurable per entity type). Cache invalidation occurs on identity status change (suspend, retire, archive).

## Resolution API

### REST (over ACF)

| Operation | ACF Endpoint | Method | Request | Response |
|-----------|-------------|--------|---------|----------|
| Resolve identity | `ids.identity.resolve` | RPC | `{ identity_id }` | `{ identity }` |
| Resolve entity identity | `ids.identity.resolveByEntity` | RPC | `{ entity_type, entity_id }` | `{ identity }` |
| List identities | `ids.identity.list` | RPC | `{ entity_type?, status?, limit, offset }` | `{ identities, total }` |

### Message Format

All IDS messages are JSON. Every request includes an ACF envelope with the requester's identity. Every response includes a status code and the requested data or error.

```json
{
  "acf": {
    "version": "1.0",
    "message_id": "msg_001",
    "sender": "aios:engine:org:osys:001",
    "target": "aios:engine:sec:ids:001",
    "timestamp": 1700000000,
    "auth_token": "eyJ..."
  },
  "payload": {
    "identity_id": "aios:org:001:a3f2c9d2"
  }
}
```