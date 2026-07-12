# AIOS Bible — Core
## 003 — Agent Configuration

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core/Agents |
| Document ID | AIOS-BBL-002-AGX-003 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds, Law 10 — Law of Tenure |
| Source Physics | Physics/007-Capabilities.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Manage runtime configuration for agents — settings hierarchy, overrides, secret injection, configuration change management. Configuration flows through a layered system where each layer has defined precedence, and configuration changes are audited, validated, and applied with appropriate deployment strategies (hot-reload vs restart-required).

## Data Model

```typescript
interface AgentConfig {
  agentId: string;
  layers: ConfigLayer[];
  effectiveConfig: Record<string, unknown>;
  version: number;
  lastApplied: Timestamp;
  lastChangedBy: string;
  changeHistory: ConfigChangeSet[];
}

interface ConfigLayer {
  layerType: 'default' | 'template' | 'agent' | 'instance' | 'runtime';
  source: string;
  config: Record<string, unknown>;
  priority: number;
  isEncrypted: boolean;
  valid: boolean;
}

interface ConfigOverride {
  overrideId: string;
  agentId: string;
  path: string;
  value: unknown;
  layer: ConfigLayer['layerType'];
  reason: string;
  authorizedBy: string;
  appliedAt: Timestamp;
  expiresAt: Timestamp | null;
}

interface SecretBinding {
  bindingId: string;
  agentId: string;
  configPath: string;
  secretRef: string;
  secretVersion: string;
  resolvedValue: string | null;
  lastRotated: Timestamp;
  rotationPolicy: 'manual' | 'automatic';
}

interface ConfigValidation {
  configId: string;
  agentId: string;
  rules: ConfigValidationRule[];
  result: 'valid' | 'invalid' | 'warning';
  violations: ConfigViolation[];
  validatedAt: Timestamp;
}

interface ConfigChangeSet {
  changeSetId: string;
  agentId: string;
  changes: ConfigChange[];
  changeType: 'hot-reload' | 'restart-required';
  reason: string;
  authorizedBy: string;
  appliedAt: Timestamp;
  rollbackRef: string | null;
  status: 'pending' | 'applied' | 'rolled-back' | 'failed';
}

interface ConfigChange {
  path: string;
  oldValue: unknown;
  newValue: unknown;
  layer: ConfigLayer['layerType'];
}
```

## Core Concepts / Operations

### Configuration Layers (Default → Template → Agent → Instance → Runtime Override)
Configuration is organized in five layers, each with ascending priority:
1. **Default** — system-wide defaults baked into the agent runtime
2. **Template** — values defined in the agent's genome template (from AGS)
3. **Agent** — agent-specific settings applied at creation or through configuration management
4. **Instance** — per-instance overrides for specific deployment contexts
5. **Runtime Override** — ephemeral overrides for debugging or emergency changes (volatile, not persisted)

### Override Precedence
Higher-numbered layers override lower-numbered layers on a per-key basis. Runtime overrides always win. Overrides can be scoped to specific paths (e.g., `capabilities.speech.volume`) and may include expiration dates for temporary changes.

### Secret Binding from SSM
Sensitive configuration values (API keys, credentials, tokens) are never stored in config layers directly. Instead, a SecretBinding references a secret in SSM by its secretRef and optional version. At config load time, the binding is resolved and the value injected into the effective config. Secret rotation is supported through version updates.

### Config Validation on Apply
Every configuration change is validated before application. Validation rules include: type checking, value range enforcement, path existence, dependency consistency, and capability bound compliance. Configurations that violate rules are rejected with structured violation details.

### Config Change Audit Trail
All configuration changes are recorded in a ConfigChangeSet with the previous and new values, change reason, authorizing identity, and timestamp. Change sets support rollback by referencing the previous configuration snapshot. The history is append-only and immutable.

### Hot-Reload vs Restart-Required Configs
Configuration keys are classified as either hot-reloadable (changes take effect immediately without agent restart) or restart-required (changes need agent restart). Hot-reload applies to runtime behavior parameters (thresholds, timeouts, feature flags). Restart-required applies to structural settings (capability bindings, policy bindings, resource limits). Classification is defined in the template schema.

## Internal Interfaces

```typescript
interface ConfigManager {
  loadConfig(agentId: string): Promise<AgentConfig>;
  getEffectiveConfig(agentId: string): Promise<Record<string, unknown>>;
  applyOverride(agentId: string, override: ConfigOverride): Promise<ConfigChangeSet>;
  applyChangeSet(agentId: string, changes: ConfigChangeSet): Promise<AgentConfig>;
  rollbackConfig(agentId: string, changeSetRef: string): Promise<AgentConfig>;
  validateConfig(config: AgentConfig): Promise<ConfigValidation>;
}

interface SecretResolver {
  resolveSecret(binding: SecretBinding): Promise<string>;
  rotateSecret(binding: SecretBinding): Promise<SecretBinding>;
  validateSecretRef(ref: string): boolean;
}

interface ConfigValidator {
  validateType(path: string, value: unknown, expectedType: string): ConfigValidationRule;
  validateRange(path: string, value: number, min: number, max: number): ConfigValidationRule;
  validateCapabilityBounds(config: AgentConfig, bounds: CapabilityBounds): ConfigValidationRule[];
  validateDependencies(config: AgentConfig, dependencies: ConfigDependency[]): ConfigValidationRule[];
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| AGX.Config.Loaded | agentId, configVersion, layerCount | Agent configuration loaded successfully |
| AGX.Config.Overridden | agentId, path, layer, oldValue, newValue | Configuration override applied |
| AGX.Config.SecretInjected | agentId, configPath, secretRef | Secret binding resolved and injected |
| AGX.Config.Validated | agentId, configVersion, result, violations | Configuration validation completed |
| AGX.Config.Changed | agentId, changeSetId, changeType, changeCount | Configuration change applied |
| AGX.Config.HotReloaded | agentId, changedPaths, timestamp | Hot-reloadable configs applied without restart |
| AGX.Config.ValidationFailed | agentId, configVersion, violations | Configuration validation rejected changes |
| AGX.Config.SecretRotated | agentId, configPath, oldSecretRef, newSecretVersion | Secret binding rotated to new version |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Configuration validation rule violation | AGX_CFG_001 | Reject change set; return structured violation details |
| Secret binding resolution failure | AGX_CFG_002 | Fail config load; agent uses previous valid config if available |
| Override path does not exist in config schema | AGX_CFG_003 | Reject override; report unknown path |
| Config change set conflict (concurrent modification) | AGX_CFG_004 | Reject change set; agent must retry with fresh base |
| Restart-required config changed without restart authorization | AGX_CFG_005 | Apply change but set pending restart flag; emit warning |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| AGX-CFG-001 | Effective config is always a deterministic merge of all layers | Algorithmic — layer merge function is pure and deterministic |
| AGX-CFG-002 | No secret value is ever stored in config layers or audit logs | Architectural — secret bindings store references only |
| AGX-CFG-003 | Every config change produces an immutable audit record | Architectural — change history is append-only |
| AGX-CFG-004 | Runtime override layer is never persisted across agent restarts | Architectural — runtime overrides are ephemeral |
| AGX-CFG-005 | Configuration must never violate capability bounds (Law 7) | Algorithmic — capability bound validation is mandatory |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Config Manager owns all agent runtime configuration; SSM owns secrets; no overlap |
| R2 — Dependency Order | Config depends on SSM (secrets), Physics/007 (bounds), and template schemas; no circular dependencies |
| R3 — DRY | Config layers eliminate per-agent duplication; template layer provides shared baseline |
| R4 — Builder Pattern | ConfigChangeSet uses builder construction for atomic multi-key updates |
| R10 — Simpler Over Complex | Five-layer hierarchy with clear numeric priority is simpler than a generic precedence engine |
| R13 — Design for Failure | Validation failures return structured violations; failed secret resolution preserves previous config |
| R14 — Paved Path | Default → Template → Agent is the standard path; Instance and Runtime overrides require elevated authorization |
| R15 — Open/Closed | New config layers can be added by defining priority and merge strategy; existing layers unchanged |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Agents/000-Overview.md | AGX overview — Configuration is part of the agent genome |
| Bible/02-Core/Agents/001-Factory.md | Factory assigns initial agent configuration at creation |
| Bible/02-Core/Agents/002-Templates.md | Templates define default parameter values and config schema |
| Bible/02-Core/Agents/004-Lifecycle.md | Restart-required config changes may trigger lifecycle transitions |
| Bible/02-Core/SSM/000-Overview.md | SSM provides secret storage and rotation for secret bindings |
| Bible/02-Core/IDS/000-Overview.md | IDS identities authorize configuration changes |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA validates capability configuration changes |
| Bible/05-Platform/004-EVS.md | EVS records config change events as evidence |
| Bible/03-Institutions/Workers/000-Overview.md | Workers consume configuration at runtime |
| Physics/007-Capabilities.md | Capability bound invariants enforced on config values |
