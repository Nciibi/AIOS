# AIOS Bible — Domains
## Communication — 001: Protocols

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-COM-001 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Protocols layer defines the communication protocol specifications for AIOS — message format standards, transport bindings, serialization schemes, channel adapter contracts, protocol negotiation, and versioning. It abstracts the detail of how a message is structured and carried from the concern of what the message means, enabling AIOS to bridge heterogeneous external systems (chat platforms, email, voice, APIs) into a unified internal representation.

Every message entering or leaving AIOS passes through this layer. The channel adapter receives raw bytes, the protocol parser validates structure against the declared protocol spec, the normalizer maps platform-specific fields to canonical fields, and the router decides where the message goes next. Protocol negotiation allows two parties to agree on a mutually supported version and serialization format before any application data flows.

## Architecture

```
Raw bytes arrive (HTTP, WebSocket, SMTP, SIP, custom)
    |
    v
+---------------------+
| Channel Adapter     |  Transport-specific listener (Slack, Discord, Email, Voice)
| (detect_channel)    |  Produces normalized transport metadata
+---------------------+
    |
    v
+---------------------+
| Protocol Parser     |  Validates structure, extracts envelope fields
| (parse_message)     |  Rejects malformed or unknown protocol messages
+---------------------+
    |
    v
+---------------------+
| Message Normalizer  |  Maps channel-specific fields to canonical message schema
| (normalize)         |  Produces internal MessageEnvelope with standard fields
+---------------------+
    |
    v
+---------------------+
| Routing Decision    |  Protocol negotiation determines target Worker or domain
| (negotiate_protocol)|  Fallback to baseline protocol on negotiation failure
+---------------------+
    |
    v
   Dispatch via ACF
```

The pipeline is symmetric for egress. Internal messages are serialized into the target channel's protocol format through the same adapter chain reversed: routing decision -> serialization -> channel adapter -> raw bytes.

## Data Model

```typescript
interface ProtocolSpec {
  protocolId: string;
  name: string;
  version: ProtocolVersion;
  serializationFormats: SerializationFormat[];
  messageSchema: Record<string, SchemaField>;
  transportBindings: TransportBinding[];
  capabilities: ProtocolCapability[];
  metadata: Record<string, string>;
}

interface MessageEnvelope {
  messageId: string;
  protocolId: string;
  protocolVersion: string;
  serializationFormat: SerializationFormat;
  headers: Record<string, string>;
  payload: unknown;
  channelId: string;
  senderId: string;
  targetId: string;
  timestamp: number;
  traceId: string;
}

interface ChannelAdapter {
  adapterId: string;
  channelType: ChannelType;
  protocolIds: string[];
  endpoint: string;
  status: AdapterStatus;
  config: ChannelConfig;
  healthCheckEndpoint?: string;
  lastOnlineAt?: number;
  metadata: Record<string, string>;
}

interface SerializationFormat {
  formatId: string;
  mimeType: string;
  compression: CompressionType;
  maxPayloadBytes: number;
  binaryEncoding: 'base64' | 'hex' | 'raw';
  schemaValidationRequired: boolean;
}

interface ProtocolVersion {
  major: number;
  minor: number;
  patch: number;
  label?: string;
  compatibleSince: string;
  deprecatedSince?: string;
  sunsetAt?: number;
}

interface NegotiationResult {
  accepted: boolean;
  protocolId: string;
  negotiatedVersion: string;
  negotiatedFormat: SerializationFormat;
  capabilities: string[];
  fallbackApplied: boolean;
  negotiationDurationMs: number;
}

interface SchemaField {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'binary';
  required: boolean;
  description: string;
  validationRegex?: string;
  maxLength?: number;
}

type ChannelType = 'chat' | 'email' | 'voice' | 'api' | 'webhook' | 'sms' | 'custom';
type AdapterStatus = 'online' | 'offline' | 'degraded' | 'starting';
type CompressionType = 'none' | 'gzip' | 'zstd' | 'lz4';
type TransportBinding = 'http' | 'websocket' | 'grpc' | 'smtp' | 'sip' | 'mqtt' | 'amqp';

interface ProtocolCapability {
  name: string;
  supported: boolean;
  sinceVersion: string;
}
```

## Core Concepts / Operations

| Operation | Preconditions | Postconditions |
|-----------|--------------|----------------|
| register_protocol | Protocol spec is valid, protocol ID is unique | Protocol added to registry; `Comm.ProtocolRegistered` emitted |
| parse_message | Raw bytes received from channel adapter | MessageEnvelope produced with validated fields; or parse failure raised |
| serialize_message | Internal envelope + target protocol spec | Serialized bytes produced in target format |
| negotiate_protocol | Two protocol specs provided | Mutually compatible version+format agreed; fallback applied if needed |
| detect_channel | Incoming transport metadata | Channel type identified; matching adapter selected or error raised |
| normalize_envelope | Raw message + detected channel | Canonical MessageEnvelope with normalized headers and payload |
| validate_schema | Envelope + protocol spec | Schema validation passes or structured validation error returned |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| IProtocolRegistry | Protocols Module | ChatWorker, SupportAgent, NotificationDispatcher | ACF query |
| IChannelAdapter | Protocols Module | ACF Gateway | ACF event |
| IMessageParser | Protocols Module | Messaging (002), Collaboration (003) | ACF sync |
| IProtocolNegotiator | Protocols Module | Channel adapters, external peers | ACF query |
| ISerializationEngine | Protocols Module | All communication modules | Internal |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Comm.ProtocolRegistered` | New protocol spec is added to registry | protocol_id, name, version, format_count, channel_types |
| `Comm.MessageParsed` | Raw bytes are successfully parsed into envelope | message_id, protocol_id, channel_type, parse_duration_ms, schema_valid |
| `Comm.MessageParseFailed` | Raw bytes fail protocol-level validation | channel_id, protocol_id, error_code, raw_size_bytes, parse_duration_ms |
| `Comm.ProtocolNegotiated` | Two peers agree on protocol version and format | protocol_id, requested_version, negotiated_version, format, fallback_used |
| `Comm.ChannelAdapterOnline` | Channel adapter starts and is ready | adapter_id, channel_type, endpoint, protocol_ids, startup_duration_ms |
| `Comm.ChannelAdapterOffline` | Channel adapter disconnects or fails | adapter_id, channel_type, reason, last_online_at, reconnect_policy |
| `Comm.SerializationError` | Serialization or deserialization fails | envelope_id, protocol_id, format, error, payload_size_bytes |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COM-PRO-001 | Unknown protocol ID requested for parsing | Error | Reject message; return supported protocol list via error envelope |
| COM-PRO-002 | Message parse failure — malformed structure | Error | Log raw payload; return structured parse error; increment parse_failure counter |
| COM-PRO-003 | Serialization error — payload exceeds format limits | Error | Reject with payload_too_large error; suggest chunking or format upgrade |
| COM-PRO-004 | Protocol version mismatch — no compatible range | Warning | Apply graceful fallback to baseline protocol; log incompatibility |
| COM-PRO-005 | Channel adapter offline or unreachable | Critical | Queue messages with TTL; attempt reconnection with exponential backoff |
| COM-PRO-006 | Schema validation failure on envelope field | Warning | Reject message with field-level validation errors; log schema drift |
| COM-PRO-007 | Negotiation timeout — peer unresponsive | Error | Fall back to lowest common protocol version; emit timeout event |
| COM-PRO-008 | Unsupported serialization format requested | Error | Return supported formats list; attempt automatic format downgrade |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COM-PRO-I-001 | Every message has exactly one protocol version identifier | Parser rejects envelopes without protocol_version; validation at gateway |
| COM-PRO-I-002 | Registered protocol IDs are globally unique | Registry enforces uniqueness constraint at registration time |
| COM-PRO-I-003 | Protocol negotiation always produces a result (accept or fallback) | Negotiator always returns NegotiationResult; fallback to baseline is mandatory |
| COM-PRO-I-004 | Schema validation is applied to every parsed message | Parser runs schema check against protocol spec before envelope is dispatched |
| COM-PRO-I-005 | Deprecated protocol versions remain parseable but block new sessions | Registry retains deprecated parsers; negotiation rejects deprecated versions for new sessions |
| COM-PRO-I-006 | Channel adapters always report status changes via event | Adapter lifecycle hooks enforce status transition event emission |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 (Modulsingularity) | Protocols layer is a focused module — protocol parsing, serialization, channel adaptation are cleanly separated |
| R2 (Capsule) | Each MessageEnvelope is a sealed capsule with immutable protocol metadata and payload |
| R3 (DRY) | Protocol specs are defined once in registry; all channels reference the same spec definitions |
| R4 (Builder) | MessageEnvelope is built incrementally through parse -> normalize -> validate pipeline stages |
| R5 (Liskov Substitution) | All channel adapters implement the same IChannelAdapter interface; interchangeable by channel type |
| R6 (DI over Singletons) | Channel adapters are injected via ACF; protocol registry is not a global singleton |
| R9 (Deterministic) | Same raw bytes + same protocol spec always yields identical parsed envelope |
| R10 (Simpler Over Complex) | Protocol negotiation is linear: propose -> accept/fallback -> confirm; no branching |
| R13 (Design for Failure) | Parse or serialization failure returns structured error envelope; pipeline never hangs |
| R14 (Paved Path) | Single paved path: register -> detect -> parse -> normalize -> route; all deviations logged |
| R15 (Open/Closed) | New protocols registered without changing parser logic; new channel adapters implement existing interface |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Communication/000-Overview.md | Overview — Protocols layer is the ingress/egress foundation for all communication |
| Bible/07-Domains/Communication/002-Messaging.md | Downstream — Parsed envelopes feed into message routing and delivery |
| Bible/07-Domains/Communication/003-Collaboration.md | Downstream — Collaboration sessions use protocol negotiation for participant sync |
| Bible/06-Services/ACF/001-Architecture.md | Transport — ACF carries normalized envelopes between protocol layer and Workers |
| Bible/06-Services/ACF/002-Messages.md | Messages — Envelope format aligns with ACF message structure |
| Bible/06-Services/ACF/003-Routing.md | Routing — Protocol negotiation determines routing decisions |
| Physics/005-Events.md | Evidence — All protocol and adapter lifecycle steps produce Events |
| Physics/007-Capabilities.md | Capabilities — Protocol capabilities are bounded by adapter capability scope |
| Physics/009-Interaction.md | Interaction — Protocols layer implements the constitutional communication invariant |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — Core principles for protocol design |
