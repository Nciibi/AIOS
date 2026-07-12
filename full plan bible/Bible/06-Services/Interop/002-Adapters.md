# AIOS Bible — Services
## 002 — Protocol Adapters

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services/Interop |
| Document ID | AIOS-BBL-006-IOP-002 |
| Source Laws | Law 3 — Law of Communication, Law 5 — Law of Identity, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Implement and manage protocol adapters for serialization/deserialization, schema validation, and cross-protocol data representation. Each adapter bridges a specific serialization format with the IOP contract system, enabling entities to communicate across format boundaries while maintaining schema integrity.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Protocol Adapter Layer                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                    Adapter Registry                     │  │
│  │  (register, lookup, health check, lifecycle mgmt)      │  │
│  └──────────┬──────────┬──────────┬──────────┬───────────┘  │
│             │          │          │          │               │
│  ┌──────────▼──┐ ┌─────▼─────┐ ┌─▼────────┐ ┌▼──────────┐  │
│  │ Protobuf    │ │ JSON      │ │MessagePack│ │ XML        │  │
│  │ Adapter     │ │ Adapter   │ │ Adapter   │ │ Adapter    │  │
│  │ (primary)   │ │(secondary)│ │(tertiary) │ │(fallback)  │  │
│  └──────────┬──┘ └─────┬─────┘ └─────┬─────┘ └──────┬────┘  │
│             │          │             │               │       │
│  ┌──────────▼──────────▼─────────────▼───────────────▼────┐  │
│  │                   Format Converter                       │  │
│  │  (Protobuf ↔ JSON, JSON ↔ MessagePack, etc.)           │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│                    IOP Protocol Adapter Layer                   │
└───────────────────────────────────────────────────────────────┘
```

## Data Model

```typescript
interface ProtocolAdapter {
  adapterId: string;
  format: SerializationFormat;
  contractId: string;
  config: AdapterConfig;
  status: 'active' | 'inactive' | 'error';
  health: () => Promise<HealthStatus>;
  serialize: <T>(payload: T) => Buffer;
  deserialize: <T>(data: Buffer) => T;
  validate: (payload: unknown) => ValidationResult;
}

type SerializationFormat = 'protobuf' | 'json' | 'messagepack' | 'xml';

interface SchemaValidator {
  validatorId: string;
  format: SerializationFormat;
  schema: unknown;
  validate: (payload: unknown) => ValidationResult;
  compile: (schema: unknown) => void;
}

interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: string[];
  duration: number;
}

interface ValidationError {
  field: string;
  code: string;
  message: string;
  constraint: string;
}

interface AdapterRegistry {
  adapters: Map<string, ProtocolAdapter>;
  register: (adapter: ProtocolAdapter) => Promise<void>;
  unregister: (adapterId: string) => Promise<void>;
  lookup: (format: SerializationFormat, contractId: string) => Promise<ProtocolAdapter>;
  listByContract: (contractId: string) => Promise<ProtocolAdapter[]>;
  healthCheck: (adapterId: string) => Promise<HealthStatus>;
}

interface AdapterConfig {
  maxPayloadSize: number;
  strictMode: boolean;
  allowUnknownFields: boolean;
  useDefaults: boolean;
  performanceProfile: 'speed' | 'size' | 'balanced';
  customOptions: Record<string, unknown>;
}

interface FormatConversion {
  conversionId: string;
  sourceFormat: SerializationFormat;
  targetFormat: SerializationFormat;
  contractId: string;
  options: ConversionOptions;
  convert: (data: Buffer) => Buffer;
}

interface ConversionOptions {
  preserveUnknownFields: boolean;
  typeCoercion: boolean;
  defaultValues: Record<string, unknown>;
}

interface HealthStatus {
  adapterId: string;
  healthy: boolean;
  lastChecked: Timestamp;
  uptime: number;
  errors: number;
  avgLatencyMs: number;
}
```

## Core Concepts / Operations

### Adapter Interface

Every ProtocolAdapter implements three core operations:
- **serialize**: Converts a typed payload object into a Buffer using the adapter's format. Applies schema constraints and field ordering per the contract definition.
- **deserialize**: Converts a Buffer back into a typed payload object. Validates the structure against the contract schema during deserialization.
- **validate**: Checks a payload against the contract schema without performing serialization. Returns structured validation results.

### Supported Formats

| Format | Priority | Use Case | Performance |
|--------|----------|----------|-------------|
| Protobuf | 1 | Internal agent-to-agent (primary) | High (binary, compact) |
| JSON | 2 | External integration, debugging | Moderate (text, human-readable) |
| MessagePack | 3 | Cross-language, space-constrained | High (binary, compact) |
| XML | 4 | Legacy system interoperability | Low (verbose, text) |

### Schema Validation Strategies

- **JSON Schema** (JSON format): Draft 2020-12 compliant. Validates field types, required fields, enums, patterns, and custom constraints.
- **Protobuf Validation** (Protobuf format): Uses protobuf message descriptors. Validates field types, required fields, oneof constraints, and wire format correctness.
- **Custom Validators** (all formats): User-defined validation functions registered per contract. Applied after format-level validation. Support custom business logic, cross-field validation, and semantic checks.

### Adapter Registry

The AdapterRegistry maintains the lifecycle of all protocol adapters:
- **register**: Adds a new adapter for a specific format and contract combination. Validates adapter configuration before registration.
- **lookup**: Returns the most appropriate adapter for a format and contract. Supports fallback to default format if exact match not found.
- **healthCheck**: Runs a diagnostic on the adapter — performs a round-trip serialize/deserialize on a test payload and reports latency, error rate, and uptime.

### Format Conversion Between Protocols

The FormatConverter handles cross-protocol transformation:
- Protobuf ↔ JSON: Field name mapping (snake_case to camelCase), type coercion for numeric/string boundaries, default value injection.
- JSON ↔ MessagePack: Direct structural mapping with type preservation. MessagePack binary strings become Buffer types in JavaScript.
- JSON ↔ XML: XML element nesting maps to JSON object nesting; attributes become prefixed fields. Array handling via repeated element convention.

### Adapter Configuration Per Contract

Each contract may specify per-format configuration: strict mode (reject unknown fields), max payload size, default value behavior, and performance profile (optimize for speed, size, or balanced).

### Performance Characteristics Per Format

| Format | Serialize (1KB) | Deserialize (1KB) | Payload Size Ratio | Memory Overhead |
|--------|-----------------|-------------------|-------------------|-----------------|
| Protobuf | ~5µs | ~8µs | 0.3x | Low |
| JSON | ~10µs | ~15µs | 1.0x | Moderate |
| MessagePack | ~7µs | ~12µs | 0.4x | Low |
| XML | ~25µs | ~35µs | 1.8x | High |

## Internal Interfaces

```typescript
interface AdapterFactory {
  createAdapter(format: SerializationFormat, contract: MessageContract, config: AdapterConfig): Promise<ProtocolAdapter>;
  destroyAdapter(adapterId: string): Promise<void>;
}

interface SchemaValidatorFactory {
  createValidator(format: SerializationFormat, schema: unknown): Promise<SchemaValidator>;
  compileValidator(schema: unknown): Promise<SchemaValidator>;
}

interface FormatConverter {
  registerConversion(source: SerializationFormat, target: SerializationFormat, contractId: string): Promise<FormatConversion>;
  convert(formatConversion: FormatConversion, data: Buffer): Promise<Buffer>;
  getAvailableConversions(): Promise<ConversionRoute[]>;
}

interface AdapterMonitor {
  recordLatency(adapterId: string, duration: number): void;
  recordError(adapterId: string, error: Error): void;
  getHealthStatus(adapterId: string): Promise<HealthStatus>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `IOP.Adap.AdapterRegistered` | adapterId, format, contractId | New adapter registered in the registry |
| `IOP.Adap.AdapterRemoved` | adapterId, format, contractId | Adapter removed from registry |
| `IOP.Adap.SerializationCompleted` | adapterId, contractId, payloadSize, duration | Payload serialized successfully |
| `IOP.Adap.DeserializationCompleted` | adapterId, contractId, payloadSize, duration | Payload deserialized successfully |
| `IOP.Adap.ValidationPassed` | adapterId, contractId, fieldsChecked | Schema validation passed |
| `IOP.Adap.ValidationFailed` | adapterId, contractId, errors | Schema validation failed |
| `IOP.Adap.FormatConverted` | conversionId, sourceFormat, targetFormat, contractId | Cross-format conversion completed |
| `IOP.Adap.AdapterError` | adapterId, errorCode, message | Adapter encountered a runtime error |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Adapter not found for format and contract | `IOP_ADAP_001` | Fall back to default adapter or return error |
| Payload exceeds max configured size | `IOP_ADAP_002` | Reject serialize/deserialize; return size limit |
| Schema validation fails | `IOP_ADAP_003` | Reject payload; return structured validation errors |
| Format conversion unsupported | `IOP_ADAP_004` | Return conversion not available; list supported routes |
| Adapter health check failure | `IOP_ADAP_005` | Mark adapter as error; trigger recovery or fallback |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IOP-ADAP-001 | serialize ∘ deserialize is identity for valid payloads within the same adapter | Algorithmic — round-trip test run during adapter registration |
| IOP-ADAP-002 | Schema validation is deterministic — same payload and schema always produces same result | Algorithmic — validators have no mutable state affecting validation |
| IOP-ADAP-003 | Format conversion between any two supported formats preserves semantic equivalence | Architectural — conversion matrix tested for all supported format pairs |
| IOP-ADAP-004 | Each contract has at least one registered adapter (default format) | Architectural — Contract Registry enforces default adapter registration on contract publish |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Protocol Adapters own serialization/deserialization; Contract Registry owns storage; Format Converter owns cross-format transformation |
| R2 — Dependency Order | Adapters depend on Contract Registry (schema lookup); no circular dependencies |
| R3 — DRY | Serialization logic is encapsulated once per adapter; contracts reference adapter IDs rather than embedding format logic |
| R9 — Deterministic | Same payload + same adapter + same config produces identical serialized output |
| R10 — Simpler Over Complex | Default JSON adapter works for most cases; Protobuf is opt-in for performance-critical paths |
| R13 — Design for Failure | Validation catches malformed payloads before serialization; health checks detect failing adapters |
| R14 — Paved Path | JSON serialization with default config covers the majority of integration scenarios |
| R15 — Open/Closed | New formats can be registered as adapters without modifying existing adapter code |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Overview.md | Parent document — IOP architecture and component map |
| 001-Protocols.md | Protocol definitions that adapters bind to for serialization |
| 003-Translation.md | Format conversion used during message translation |
| Bible/06-Services/ACF/000-Overview.md | ACF transports the serialized payloads produced by adapters |
| Physics/009-Interaction.md | Interaction invariants for message serialization and format handling |
