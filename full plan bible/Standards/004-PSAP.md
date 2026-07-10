# AIOS Standards
## 004 — PSAP Service Addressing Standards

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Standards |
| Document ID | STD-PSAP-004 |
| Source Laws | Law 2 — Non-Execution, Law 7 — Capability Bounds |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

PSAP (Platform Service Access Point) is the service addressing and routing layer. This standard defines the naming conventions, registration requirements, and addressing rules that every service must follow to register with PSAP and be discoverable by other services. For the complete PSAP specification, see `Bible/05-Platform/003-PSAP.md`.

## Service Naming

Every service must have a canonical name registered in PSAP. Names are lowercase, max 16 characters, using hyphens only for compound names.

| Naming Pattern | Example | Service Type |
|---------------|---------|-------------|
| `<abbreviation>` | `lms`, `evs`, `psap` | Core platform services |
| `<domain>-<function>` | `acf-routing`, `acf-messages` | ACF sub-services |
| `sdk-<name>` | `sdk-runtime`, `sdk-audit` | SDK-bound services |
| `ext-<name>` | `ext-claude`, `ext-codex` | External provider adapters |

## Registration Requirements

Every service registering with PSAP must provide:

| Field | Required | Format |
|-------|----------|--------|
| service_name | Yes | lowercase, no hyphens, max 16 chars |
| instance_id | Yes | UUIDv7 |
| endpoint | Yes | ACF address (topic or queue) |
| version | Yes | SemVer string |
| capabilities | Yes | Array of capability identifiers |
| health_check_endpoint | Yes | ACF topic for health check responses |
| tags | No | Key-value metadata |
| description | No | Human-readable description (max 200 chars) |

## Endpoint Format

Endpoints use ACF addressing:

```
acf://<service_name>/<instance_id>/<channel>
```

Examples:
- `acf://lms/550e8400-e29b-41d4-a716-446655440000/commands`
- `acf://evs/f47ac10b-58cc-4372-a567-0e02b2c3d479/events`
- `acf://sdk-runtime/6ba7b810-9dad-11d1-80b4-00c04fd430c8/capabilities`

## Capability Identifiers

Services declare capabilities using dot-separated identifiers:

```
<domain>.<action>
```

Examples:
- `session.create`, `session.terminate`
- `event.query`, `event.store`
- `identity.verify`, `identity.resolve`

## Health Check Contract

Every service must respond to health checks on its declared health check endpoint within the ping timeout. Response format:

```
{
  "status": "healthy | degraded | unhealthy",
  "load": 0.0,
  "uptime_seconds": 3600,
  "version": "1.0.0",
  "capabilities": ["session.create", "session.terminate"],
  "message": "optional status message"
}
```

## Heartbeat Requirements

- Heartbeat interval: 30 seconds (configurable per service)
- Missed heartbeats: 3 consecutive misses → marked unhealthy
- Recovery: successful heartbeat → restored to active
- Deregistration: 5 consecutive misses → automatic deregistration

## Load Balancing Strategy

PSAP supports the following load balancing strategies:

| Strategy | Selection | Use Case |
|----------|-----------|----------|
| round-robin | Sequential instance selection | Stateless services |
| least-loaded | Lowest load metric | Stateful services |
| random | Random instance | Test/staging |
| sticky | Same instance for same caller | Session-affine services |

Services declare their preferred strategy at registration. Default is `round-robin`.

## Addressing Standards

### Service Resolution
- Resolve by `service_name` only (no direct instance addressing)
- PSAP returns all healthy instances for a service
- Caller uses PSAP-provided endpoint for communication

### Prohibited Patterns
- Direct IP or hostname addressing
- Hardcoded service endpoints
- Bypassing PSAP for service discovery
- Caching resolved endpoints beyond TTL (60 seconds)

## Error Codes

| Code | Description |
|------|-------------|
| PSAP_001 | Service not found |
| PSAP_002 | No healthy instances available |
| PSAP_003 | Instance not found |
| PSAP_004 | Registration authentication failed |
| PSAP_005 | Duplicate registration |
| PSAP_006 | Heartbeat threshold exceeded |

## Cross-Cutting Concerns

### Security
Service registration requires authentication. Impersonating a service or registering under a false name is a security violation. Deregistration is verified to prevent rogue instance removal.

### Evidence
Every registration, deregistration, and health state change produces an Event. PSAP events are part of the system evidence chain.

### Lifecycle
Services follow: Registered → Active ↔ Degraded → Unhealthy → Deregistered. Lifecycle managed by PSAP with heartbeat monitoring.

### Capability Bounds
Services declare their capabilities at registration. PSAP enforces capability-based routing — services only receive requests for declared capabilities.

### Interoperability
PSAP is the universal addressing layer. All services must register. No service may communicate outside PSAP resolution. Cross-instance PSAP is handled through Federation.

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/05-Platform/003-PSAP.md | PSAP complete specification |
| Bible/06-Services/ACF/003-Routing.md | ACF routing — PSAP integration |
| Bible/06-Services/ACF/001-Architecture.md | ACF architecture |
| 001-Naming-Conventions.md | Service naming conventions |
