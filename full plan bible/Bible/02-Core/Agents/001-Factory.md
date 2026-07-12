# AIOS Bible — Core
## 001 — Agent Factory

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core/Agents |
| Document ID | AIOS-BBL-002-AGX-001 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds, Law 10 — Law of Tenure |
| Source Physics | Physics/007-Capabilities.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Create new agents from genome templates — composition, validation, and initial lifecycle stage assignment. AGS provides genome templates; AGX Factory assembles agents from those templates, validates the resulting blueprint against capability bounds and lifecycle rules, assigns a unique identity via IDS, and places the agent in its initial lifecycle stage (Nascent by default).

## Data Model

```typescript
interface AgentBlueprint {
  blueprintId: string;
  templateRef: string;
  templateVersion: string;
  composition: GenomeCompositionRequest;
  capabilityInjections: CapabilityInjection[];
  identity: AgentIdentity | null;
  assignedStage: AgentLifecycleStage;
  validationResults: ValidationResult[];
  status: 'draft' | 'validated' | 'assembled' | 'rejected';
  createdAt: Timestamp;
  assembledAt: Timestamp | null;
}

interface GenomeCompositionRequest {
  baseTemplate: string;
  overlayTemplates: string[];
  parameters: Record<string, unknown>;
  constraints: Constraint[];
  compositionStrategy: 'merge' | 'override' | 'strict-merge';
}

interface AgentIdentity {
  agentId: string;
  agentName: string;
  agentType: string;
  identityRef: string;
  issuedAt: Timestamp;
  issuedBy: string;
}

interface CapabilityInjection {
  capabilityId: string;
  capabilityName: string;
  sourceTemplate: string;
  injectionPoint: string;
  parameters: Record<string, unknown>;
  required: boolean;
  validationRef: string;
}

interface FactoryEvent {
  eventId: string;
  eventType: string;
  blueprintId: string;
  agentId: string | null;
  timestamp: Timestamp;
  details: Record<string, unknown>;
}
```

## Core Concepts / Operations

### Blueprint-to-Genome Assembly
The Factory receives a GenomeCompositionRequest referencing a base template and optional overlay templates. It resolves each template from the AGS Template Registry, merges them according to the composition strategy (merge, override, or strict-merge), applies parameter bindings, and produces a complete AgentBlueprint.

### Capability Injection from Templates
CapabilityInjections are extracted from the composed templates and injected into the blueprint. Each injection specifies the capability, source template, injection point, and parameters. Required injections must succeed for the blueprint to proceed; optional injections may be skipped with a warning.

### Identity Assignment (IDS Integration)
Once the blueprint is validated, the Factory requests a unique agent identity from IDS. The identity includes the agentId, agentName, agentType, and a signed identity reference. The identity is bound to the blueprint and cannot be changed after assembly.

### Initial Stage Assignment
New agents are assigned to the Nascent stage by default. The Factory sets the initial lifecycle stage in the blueprint before assembly. Stage assignment respects Law 6 (Lifecycle Compliance) and the agent's capability profile — agents with insufficient capabilities cannot be assigned to higher stages.

### Validation Gates at Creation
Every blueprint passes through validation gates before assembly:
1. Template resolution — all referenced templates exist and are compatible
2. Parameter validation — all required parameters are provided and satisfy constraints
3. Capability bound check — injected capabilities do not exceed Law 7 bounds
4. Composition integrity — merged templates produce a consistent genome
5. Lifecycle compliance — assigned stage is valid and achievable

### Factory Pipeline
The pipeline executes sequentially: Request → Validate → Inject Capabilities → Assign Identity → Assemble → Emit Created Event. Each stage publishes a corresponding event. Failure at any stage emits a Failure event and transitions the blueprint to rejected status.

## Internal Interfaces

```typescript
interface AgentFactory {
  createAgentFromBlueprint(request: GenomeCompositionRequest): Promise<AgentBlueprint>;
  validateBlueprint(blueprint: AgentBlueprint): Promise<ValidationResult[]>;
  injectCapabilities(blueprint: AgentBlueprint): Promise<AgentBlueprint>;
  assignIdentity(blueprint: AgentBlueprint): Promise<AgentIdentity>;
  assembleAgent(blueprint: AgentBlueprint): Promise<AgentIdentity>;
}

interface BlueprintValidator {
  validateTemplateRef(templateRef: string, version: string): ValidationResult;
  validateParameters(params: Record<string, unknown>, constraints: Constraint[]): ValidationResult[];
  validateCapabilityBounds(injections: CapabilityInjection[]): ValidationResult;
  validateComposition(request: GenomeCompositionRequest): ValidationResult;
  validateLifecycleStage(stage: AgentLifecycleStage, capabilities: CapabilityInjection[]): ValidationResult;
}

interface IdentityResolver {
  requestIdentity(blueprint: AgentBlueprint): Promise<AgentIdentity>;
  validateIdentity(identity: AgentIdentity): boolean;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| AGX.Factory.AgentCreationRequested | blueprintId, templateRef, parameters | Factory pipeline initiated for a new agent |
| AGX.Factory.AgentBlueprintValidated | blueprintId, validationResults | Blueprint passed all validation gates |
| AGX.Factory.CapabilitiesInjected | blueprintId, injections, successCount | Capabilities injected into blueprint |
| AGX.Factory.IdentityAssigned | blueprintId, agentId, identityRef | IDS identity assigned to new agent |
| AGX.Factory.AgentCreated | blueprintId, agentId, stage, templateRef | Agent successfully created from blueprint |
| AGX.Factory.AgentCreationFailed | blueprintId, reason, failedGate | Assembly pipeline failed at a specific gate |
| AGX.Factory.BlueprintRejected | blueprintId, rejectionReasons, violations | Blueprint rejected during validation |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Template reference not found in AGS | AGX_FAC_001 | Reject blueprint; report unresolved template |
| Required parameter missing or invalid | AGX_FAC_002 | Reject blueprint; list missing/invalid parameters |
| Capability injection exceeds bounds | AGX_FAC_003 | Reject blueprint; identify offending capabilities |
| IDS identity assignment failure | AGX_FAC_004 | Fail pipeline; retry with backoff, then escalate |
| Composition merge conflict or inconsistency | AGX_FAC_005 | Reject blueprint; report merge conflict details |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| AGX-FAC-001 | Every agent has exactly one factory blueprint at creation | Architectural — Factory issues unique blueprintId per invocation |
| AGX-FAC-002 | Identity assignment is irrevocable after assembly | Architectural — IDS identity is bound at assembly and immutable |
| AGX-FAC-003 | All required capability injections must succeed before assembly | Algorithmic — pipeline halts if required injection fails |
| AGX-FAC-004 | No agent may be created with capabilities exceeding Law 7 bounds | Algorithmic — capability bound check is mandatory gate |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | AGX Factory owns agent creation exclusively; AGS owns template definitions; IDS owns identity |
| R2 — Dependency Order | Factory depends on AGS (templates), IDS (identity), Physics/007 (bounds); no circular dependencies |
| R3 — DRY | Blueprint validation rules are defined once in BlueprintValidator; all gates reuse them |
| R4 — Builder Pattern | AgentBlueprint uses builder construction for incremental assembly through the pipeline |
| R10 — Simpler Over Complex | Composition strategies are declarative (three modes); no imperative merge scripts |
| R13 — Design for Failure | Each gate emits a specific failure event; partial assembly state is preserved for debugging |
| R14 — Paved Path | Default composition is single-template merge with Nascent stage; custom paths require template overrides |
| R15 — Open/Closed | New validation gates can be added without modifying existing gates; pipeline is extensible |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Agents/000-Overview.md | AGX overview — Factory is a sub-component of AGX |
| Bible/02-Core/Agents/002-Templates.md | AGS template registry provides genome templates for assembly |
| Bible/02-Core/Agents/003-Configuration.md | Agent configuration is applied after factory assembly |
| Bible/02-Core/Agents/004-Lifecycle.md | Factory assigns initial lifecycle stage; Lifecycle manages transitions |
| Bible/02-Core/AGS/000-Overview.md | AGS produces the genome templates consumed by Factory |
| Bible/04-Execution/Security/IDS/000-Overview.md | IDS provides identity assignment for new agents |
| Bible/04-Execution/Security/SSM/000-SSM.md | SSM provides secrets for capability parameter injection |
| Bible/00-Foundations/008-Object-Lifecycle.md | Object Lifecycle governs stage assignment rules |
| Physics/007-Capabilities.md | Capability bound invariants enforced at creation |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants for initial stage |
