# AIOS Bible — Core
## 002 — Agent Templates

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core/Agents |
| Document ID | AIOS-BBL-002-AGX-002 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds, Law 10 — Law of Tenure |
| Source Physics | Physics/007-Capabilities.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Define, version, and manage agent genome templates used by the Factory to create agents. Templates are composable (multiple templates can be merged), inheritable (templates can extend parent templates), and validated against constraint rules. The Template Registry is the authoritative source for all genome template definitions.

## Data Model

```typescript
interface AgentTemplate {
  templateId: string;
  name: string;
  description: string;
  version: TemplateVersion;
  parentTemplate: string | null;
  capabilities: TemplateCapability[];
  parameters: TemplateParameter[];
  playbooks: TemplatePlaybook[];
  policies: TemplatePolicy[];
  constraints: Constraint[];
  metadata: Record<string, string>;
  status: 'active' | 'deprecated' | 'retired';
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

interface TemplateVersion {
  templateId: string;
  version: string;
  semver: string;
  changelog: string;
  previousVersion: string | null;
  compatibility: string[];
  publishedAt: Timestamp;
  publishedBy: string;
}

interface TemplateComposition {
  compositionId: string;
  baseTemplate: string;
  baseVersion: string;
  overlayTemplates: { templateId: string; version: string }[];
  mergedTemplate: AgentTemplate;
  mergeStrategy: 'merge' | 'override' | 'strict-merge';
  conflicts: CompositionConflict[];
  validatedAt: Timestamp;
  valid: boolean;
}

interface TemplateInheritance {
  childTemplate: string;
  parentTemplate: string;
  depth: number;
  inheritedCapabilities: string[];
  overriddenCapabilities: string[];
  inheritedParameters: string[];
  overriddenParameters: string[];
  inheritanceChain: string[];
}

interface TemplateParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required: boolean;
  defaultValue: unknown;
  description: string;
  constraints: Constraint[];
  sensitive: boolean;
}

interface Constraint {
  field: string;
  rule: string;
  value: unknown;
  message: string;
  severity: 'error' | 'warning';
}
```

## Core Concepts / Operations

### Template Structure
Each template defines a complete agent genome fragment: capabilities, parameters, playbooks, policies, and constraints. Templates are identified by a unique templateId and versioned using semantic versioning. Every template has a status (active, deprecated, retired) that controls whether it can be used for new agent creation.

### Versioning Scheme
Templates follow semver: MAJOR.MINOR.PATCH. MAJOR version changes indicate breaking changes to the template interface. MINOR version changes add backward-compatible capabilities or parameters. PATCH version changes fix defects or update metadata. The Template Registry maintains the full version history and compatibility matrix.

### Composition (Merge Multiple Templates)
Templates can be composed by combining a base template with overlay templates. Three merge strategies are supported:
- **merge** — overlay capabilities and parameters are added alongside base; conflicts produce warnings
- **override** — overlay values replace base values on conflict
- **strict-merge** — any conflict between base and overlay causes composition to fail

### Inheritance Hierarchy
Templates can declare a parent template to inherit capabilities, parameters, and policies. Inheritance is acyclic and depth-limited (max 5 levels). Child templates can override inherited capabilities and parameters. The inheritance chain is explicit and validated at template creation time.

### Parameterization with Constraints
Template parameters are typed and may have constraints: value ranges (for numbers), allowed values (for strings), regex patterns, length limits, or custom validation rules. Parameters marked as sensitive are bound to SSM secrets at agent creation time rather than stored in the template directly.

### Template Validation Rules
Every template version undergoes validation on publish:
1. Structure integrity — all required fields present, types match
2. Inheritance validity — parent exists, no cycles, depth within limit
3. Constraint consistency — constraints are self-consistent and satisfiable
4. Capability bound check — declared capabilities do not exceed Law 7 bounds
5. Playbook reference integrity — all referenced playbooks exist

### Template Registry
The Template Registry stores, versions, and serves all agent templates. It provides lookup by templateId and version, composition validation, inheritance chain resolution, and lifecycle management (deprecation, retirement). The Registry is the single source of truth for genome template definitions consumed by the AGX Factory.

## Internal Interfaces

```typescript
interface TemplateRegistry {
  getTemplate(templateId: string, version?: string): Promise<AgentTemplate>;
  publishTemplate(template: AgentTemplate): Promise<TemplateVersion>;
  deprecateTemplate(templateId: string, reason: string): Promise<void>;
  retireTemplate(templateId: string, reason: string): Promise<void>;
  composeTemplates(request: TemplateComposition): Promise<AgentTemplate>;
  resolveInheritance(templateId: string): Promise<TemplateInheritance>;
  listTemplates(filter?: TemplateFilter): Promise<AgentTemplate[]>;
}

interface TemplateValidator {
  validateStructure(template: AgentTemplate): ValidationResult[];
  validateInheritance(template: AgentTemplate): ValidationResult;
  validateConstraints(template: AgentTemplate): ValidationResult[];
  validateCapabilityBounds(template: AgentTemplate): ValidationResult;
  validatePlaybookRefs(template: AgentTemplate): ValidationResult[];
  validateComposition(composition: TemplateComposition): ValidationResult[];
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| AGX.Template.Created | templateId, version, name | New template published to registry |
| AGX.Template.Versioned | templateId, oldVersion, newVersion, changelog | New version of existing template published |
| AGX.Template.Composed | compositionId, baseTemplate, overlayTemplates | Template composition performed |
| AGX.Template.CompositionValidated | compositionId, valid, conflicts | Composition validation completed |
| AGX.Template.Deprecated | templateId, reason, deprecationDate | Template marked as deprecated |
| AGX.Template.Retired | templateId, reason, retirementDate | Template fully retired from registry |
| AGX.Template.ConstraintViolation | templateId, field, rule, value | Constraint validation failed on template operation |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Template reference not found by ID or version | AGX_TPL_001 | Return not found; no template created |
| Inheritance cycle detected or depth exceeded | AGX_TPL_002 | Reject template publish; report cycle path |
| Composition merge conflict in strict mode | AGX_TPL_003 | Reject composition; report conflicting fields |
| Template constraint unsatisfiable | AGX_TPL_004 | Reject template publish; report constraint details |
| Attempted to use deprecated or retired template for creation | AGX_TPL_005 | Reject operation; suggest active template version |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| AGX-TPL-001 | Every template has a globally unique templateId | Architectural — Registry enforces uniqueness on publish |
| AGX-TPL-002 | Template inheritance forms a directed acyclic graph | Algorithmic — cycle detection on every inheritance declaration |
| AGX-TPL-003 | Template composition produces a valid, self-consistent genome | Algorithmic — composition validated before storage |
| AGX-TPL-004 | No template may declare capabilities exceeding Law 7 bounds | Algorithmic — capability bound check on publish |
| AGX-TPL-005 | Retired templates are immutable and cannot be reactivated | Architectural — retired status is terminal |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Template Registry owns all template definitions; AGX Factory consumes them; AGS produces initial templates |
| R2 — Dependency Order | Templates depend on Physics/007 (bounds) and SSM (secret parameters); no downstream dependencies |
| R3 — DRY | Template inheritance eliminates duplication; child templates only specify differences from parent |
| R4 — Builder Pattern | TemplateComposition uses builder construction for incremental merge of overlay templates |
| R10 — Simpler Over Complex | Three composition strategies (merge, override, strict-merge) cover all use cases; no imperative merge DSL |
| R13 — Design for Failure | Composition validation returns structured conflict reports; constraint violations identify exact failing rule |
| R14 — Paved Path | Single-template inheritance (one parent) and merge composition are the default; multi-parent and strict mode require explicit opt-in |
| R15 — Open/Closed | New constraint types can be added without modifying existing validation rules |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Agents/000-Overview.md | AGX overview — Templates provide the genome definitions AGX evolves |
| Bible/02-Core/Agents/001-Factory.md | Factory consumes templates to assemble agents |
| Bible/02-Core/Agents/003-Configuration.md | Template parameters may bind to agent configuration |
| Bible/02-Core/Agents/004-Lifecycle.md | Template lifecycle (active/deprecated/retired) mirrors agent lifecycle concepts |
| Bible/02-Core/AGS/000-Overview.md | AGS produces and maintains the genome templates |
| Bible/04-Execution/Security/SSM/000-SSM.md | SSM provides secret binding for sensitive template parameters |
| Physics/007-Capabilities.md | Capability bound invariants enforced on template capabilities |
| Physics/006-Lifecycles.md | Template lifecycle states align with object lifecycle principles |
