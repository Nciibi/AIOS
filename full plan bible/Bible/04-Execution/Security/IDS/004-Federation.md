# AIOS Bible — Identity Service (IDS)
## 004 — Identity Federation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Identity |
| Document ID | AIOS-BIBLE-IDS-004 |
| Source Laws | Law 5 — Law of Identity |
| Source Physics | Physics/001-Identity.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Intra-Instance Federation (Same AIOS Instance)

All identity operations within a single AIOS instance flow through the single IDS instance (or cluster). No federation needed.

## Cross-Instance Federation (Multiple AIOS Instances)

When two AIOS instances need to interoperate (e.g., cross-system Mission collaboration), identities must be resolvable across instances. IDS supports:

| Mechanism | Description | Use Case |
|-----------|-------------|-------------|
| **Direct Resolution** | Instance A's IDS queries Instance B's IDS over authenticated ACF bridge | Trusted pair of instances with pre-established ACF connection |
| **Proxy Resolution** | A trusted intermediary holds resolution rights for both instances | Multi-instance federation through a hub |
| **External Identity Provider** | Identities are anchored to an external authority (e.g., DNS, SSO provider) | User identity federation with external auth systems |

## Federated Identity Record Structure

Cross-instance identity resolution produces a federated identity record:

```json
{
  "identity_id": "aios:org:fed:a1b2c3d4",
  "entity_type": "org_federated",
  "home_instance": "aios://instance-b.internal:8443",
  "foreign_identity": "aios:org:b3:a3f2c9d2",
  "status": "active",
  "provenance": {
    "verified_by": "aios://instance-b.internal:8443/ids",
    "trust_chain": ["aios://instance-a.ids", "aios://instance-b.ids"]
  }
}
```

## Identity Verification at Pipeline Level

Identity verification is the first stage of the Security Council's verification pipeline. The pipeline checks:

| Check | Condition | Failure Action |
|-------|-----------|---------------|
| Identity exists | `resolveIdentity` returns a record | Deny action, log as security event |
| Identity is active | `status == Active` | Deny action, log as security event |
| Identity is authentic | Cryptographic signature matches | Deny action, escalate as identity spoofing |
| Entity binding matches | `entity_id` matches the requesting entity | Deny action, log as security event |

The verification result is cached by the Security Council for the identity's verification TTL (default: 60 seconds, configurable per entity type). Cache invalidation occurs on identity status change (suspend, retire, archive).