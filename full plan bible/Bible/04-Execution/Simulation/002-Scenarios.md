# AIOS Bible — Execution
## 002 — Scenarios

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Simulation |
| Document ID | AIOS-BBL-004-SIM-002 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Scenario definition language, validation, versioning, and lifecycle management for simulation scenarios. Scenarios encode "what if" questions as structured, typed, versioned definitions that can be created, discovered, reused, and chained for hypothesis exploration.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Scenario System                            │
│                                                              │
│  ┌───────────────────┐    ┌────────────────────────────┐    │
│  │   Scenario Store   │    │    Scenario Builder         │    │
│  │  (versioned,       │◄───│  - create                  │    │
│  │   immutable after  │    │  - validate                │    │
│  │   first run)       │    │  - createVariant           │    │
│  └─────────┬─────────┘    │  - createTemplate           │    │
│            │              └────────────────────────────┘    │
│            │                                               │
│  ┌─────────▼─────────┐    ┌────────────────────────────┐    │
│  │ Scenario Registry  │    │   Template Engine           │    │
│  │ - search           │    │  - parameter binding        │    │
│  │ - collections      │    │  - default injection        │    │
│  │ - lifecycle mgmt   │    │  - constraint validation    │    │
│  └───────────────────┘    └────────────────────────────┘    │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │            Variant Manager                            │    │
│  │  - derive variant from base + changes                 │    │
│  │  - maintain variant lineage (parent → child chain)   │    │
│  │  - compare variants (diff of parameters, criteria)   │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### Scenario Lifecycle

Scenarios progress through a defined lifecycle:

```
┌───────┐  validate()  ┌────────┐  first run  ┌──────────┐
│ draft │─────────────►│ active │────────────►│ immutable │
└───────┘              └────────┘             └──────────┘
                           │                       │
                           │ deprecate()           │ (version bump
                           ▼                       │  creates new
                       ┌────────────┐              │  draft)
                       │ deprecated │              │
                       └─────┬──────┘              │
                             │ retire()            │
                             ▼                     │
                        ┌─────────┐                │
                        │ retired │◄───────────────┘
                        └─────────┘
```

- **draft**: Being edited; not yet validated or run
- **active**: Validated and ready for simulation; can still be edited (minor changes create new version)
- **immutable**: Has been referenced by at least one simulation run; cannot be changed (edits create a new version)
- **deprecated**: Still available but marked for removal; consumers should migrate
- **retired**: No longer available for new simulations; archived for audit

### Scenario Structure

Each scenario captures:
- **Identity**: scenarioId, name, domain(s), version
- **State**: initialState snapshot reference and state data
- **Actions**: ordered list of SimulatedAction with scheduling and dependency information
- **Parameters**: typed parameters that parameterize the simulation behavior
- **Constraints**: bounds and validation rules for parameters
- **Success Criteria**: Criterion array defining how to evaluate outcomes
- **Metadata**: evidenceRef, tags, description, author, created/updated timestamps

### Parameterization

Scenarios accept typed parameters that control simulation behavior:
- **Input parameters**: Values injected before simulation (e.g., budget allocation, agent count)
- **Output parameters**: Values collected after simulation (e.g., final resource level, completion time)
- **Parameter constraints**: Type, range, enum, regex, or custom validation functions
- **Default values**: Parameters can have defaults, making scenarios easy to run out of the box

### Template System

Templates enable reusable scenario blueprints:
- Templates define structure with parameter placeholders (`${paramName}`)
- Parameters are resolved at instantiation time via the Template Engine
- Constraints and validation rules are inherited from the template
- Templates can extend other templates (template inheritance)

### Variant Creation

Variants support hypothesis testing:
- A variant is derived from a base scenario with a set of targeted changes
- Changes can modify parameters, actions, success criteria, or duration
- Variants maintain a parent reference for lineage tracking
- Multiple variants can be compared via multi-run analysis

### Scenario Versioning

- Scenarios are versioned using monotonic integers (1, 2, 3, ...)
- After the first simulation run references a scenario, the definition becomes immutable
- Any edit creates a new version (not a mutation of the existing one)
- Old versions remain in the store for replay verification and audit
- Version history is preserved for lineage analysis

### Collections and Discovery

- Scenarios are organized into collections (logical groups)
- Collections can nest (collection hierarchy)
- Scenarios are searchable by name, domain, tag, author, status, and version
- Discovery returns the latest active version by default

## Data Model

```typescript
interface Scenario {
  scenarioId: string;
  name: string;
  description: string;
  domain: SimulationDomain;
  multiDomain?: SimulationDomain[];
  version: number;
  status: ScenarioStatus;
  initialState: SimulationState;
  actions: SimulatedAction[];
  parameters: ScenarioParameter[];
  duration: Duration;
  successCriteria: Criterion[];
  tags: string[];
  author: string;
  templateRef: string | null;
  parentScenarioId: string | null;
  evidenceRef: string | null;
  createdAt: Timestamp;
  updatedAt: Timestamp;
  constraints: ScenarioConstraint[];
}

interface ScenarioVersion {
  scenarioId: string;
  version: number;
  definition: Scenario;
  status: ScenarioStatus;
  changelog: string;
  createdAt: Timestamp;
  supersedesVersion: number | null;
}

type ScenarioStatus = 'draft' | 'active' | 'immutable' | 'deprecated' | 'retired';

interface ScenarioParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'enum' | 'record';
  direction: 'input' | 'output' | 'both';
  required: boolean;
  defaultValue?: unknown;
  constraints: ParameterConstraint[];
  description: string;
}

interface ParameterConstraint {
  type: 'range' | 'enum' | 'regex' | 'minLength' | 'maxLength' | 'custom';
  value: unknown;
  message: string;
}

interface ScenarioTemplate {
  templateId: string;
  name: string;
  description: string;
  body: string; // scenario definition with ${param} placeholders
  parameters: ScenarioParameter[];
  extends: string | null;
  constraints: ScenarioConstraint[];
  version: number;
  createdAt: Timestamp;
}

interface ScenarioVariant {
  variantId: string;
  baseScenarioId: string;
  baseVersion: number;
  changes: ScenarioChange[];
  derivedScenario: Scenario;
  lineage: string[]; // ordered list of ancestor scenarioIds
  createdAt: Timestamp;
}

interface ScenarioChange {
  path: string; // e.g. "parameters.budgetAllocation"
  op: 'set' | 'unset' | 'append' | 'remove';
  value: unknown;
}

interface ScenarioCollection {
  collectionId: string;
  name: string;
  description: string;
  parentCollectionId: string | null;
  scenarioIds: string[];
  filterCriteria: CollectionFilter | null;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

interface CollectionFilter {
  domain?: SimulationDomain[];
  status?: ScenarioStatus[];
  tags?: string[];
  author?: string;
  createdAfter?: Timestamp;
  createdBefore?: Timestamp;
}

interface ScenarioConstraint {
  type: 'domain' | 'parameter' | 'dependency' | 'duration';
  rule: string;
  message: string;
}

interface ScenarioSearchResult {
  scenarioId: string;
  name: string;
  domain: SimulationDomain;
  version: number;
  status: ScenarioStatus;
  tags: string[];
  matchScore: number;
}
```

## Core Concepts / Operations

- **Scenario Creation**: Builder constructs scenario with validation; defaults applied for optional fields
- **Validation**: Structural validation (types, required fields) + constraint validation (parameters, dependencies, domain)
- **Template Instantiation**: Fill template placeholders with parameter values; validate against template constraints
- **Variant Derivation**: Clone base scenario, apply changes, validate derived scenario; link lineage
- **Version Bump**: When scenario referenced by a simulation run, next edit creates a new version
- **Lifecycle Transition**: Validate transition rules (e.g., retired → active not allowed, draft → active requires validation)
- **Search and Discovery**: Query by domain, status, tags, author, date range; sorted by match score

## Internal Interfaces

```typescript
interface ScenarioBuilder {
  create(params: ScenarioParams): Promise<Scenario>;
  validate(scenario: Scenario): ValidationResult;
  createVariant(baseScenarioId: string, changes: ScenarioChange[]): Promise<Scenario>;
  createTemplate(definition: ScenarioTemplate): Promise<ScenarioTemplate>;
  instantiateTemplate(templateId: string, params: Record<string, unknown>): Promise<Scenario>;
}

interface ScenarioStore {
  save(scenario: Scenario): Promise<void>;
  get(scenarioId: string, version?: number): Promise<Scenario | null>;
  getLatest(scenarioId: string): Promise<Scenario | null>;
  getVersionHistory(scenarioId: string): Promise<ScenarioVersion[]>;
  delete(scenarioId: string, version: number): Promise<void>;
}

interface TemplateEngine {
  register(template: ScenarioTemplate): Promise<void>;
  instantiate(templateId: string, params: Record<string, unknown>): Promise<Scenario>;
  resolvePlaceholders(template: string, params: Record<string, unknown>): string;
  validateConstraints(template: ScenarioTemplate, params: Record<string, unknown>): ValidationResult;
}

interface VariantManager {
  propose(baseScenarioId: string, changes: ScenarioChange[]): Promise<Scenario>;
  getLineage(variantId: string): Promise<Scenario[]>;
  compare(variantA: string, variantB: string): Promise<VariantDiff>;
}

interface ScenarioDiscovery {
  search(query: ScenarioQuery): Promise<ScenarioSearchResult[]>;
  getCollection(collectionId: string): Promise<ScenarioCollection>;
  listCollections(parentId?: string): Promise<ScenarioCollection[]>;
  addToCollection(collectionId: string, scenarioId: string): Promise<void>;
}

interface LifecycleManager {
  transition(scenarioId: string, version: number, targetStatus: ScenarioStatus): Promise<void>;
  getAvailableTransitions(currentStatus: ScenarioStatus): ScenarioStatus[];
  validateTransition(scenario: Scenario, targetStatus: ScenarioStatus): ValidationResult;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `SIM.Scen.Created` | scenarioId, version, domain | New scenario definition created |
| `SIM.Scen.Validated` | scenarioId, version, isValid, errors | Scenario validation completed |
| `SIM.Scen.Activated` | scenarioId, version | Scenario transitioned to active status |
| `SIM.Scen.Versioned` | scenarioId, oldVersion, newVersion, changelog | New version created from existing scenario |
| `SIM.Scen.Templated` | templateId, scenarioId | Scenario instantiated from a template |
| `SIM.Scen.VariantCreated` | variantId, baseScenarioId, changeCount | Variant scenario derived from base |
| `SIM.Scen.Deprecated` | scenarioId, version, reason | Scenario marked as deprecated |
| `SIM.Scen.Retired` | scenarioId, version | Scenario retired and archived |
| `SIM.Scen.NotFound` | scenarioId, version | Requested scenario not found in store |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Scenario fails structural validation | `SIM_SCEN_001` | Reject creation; return detailed validation errors |
| Scenario already exists at target version | `SIM_SCEN_002` | Reject save; increment version or use unique scenarioId |
| Template parameter not found | `SIM_SCEN_003` | Reject instantiation; list missing parameters |
| Variant changes produce invalid scenario | `SIM_SCEN_004` | Reject variant creation; return validation errors from derived scenario |
| Lifecycle transition not allowed | `SIM_SCEN_005` | Reject transition; list available transitions from current status |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SIM-SCEN-001 | Scenario definitions are immutable after the first simulation run references them | Architectural — ScenarioStore enforces read-only after evidenceRef is set |
| SIM-SCEN-002 | Scenario versions are strictly increasing (no gaps, no duplicates) | Algorithmic — version assignment is monotonic |
| SIM-SCEN-003 | Every variant maintains a parent reference forming an acyclic lineage | Algorithmic — VariantManager validates no circular parent references |
| SIM-SCEN-004 | Template instantiation produces a fully resolved scenario (no unresolved placeholders) | Algorithmic — TemplateEngine validates all placeholders are bound |
| SIM-SCEN-005 | A retired scenario cannot be reactivated or referenced by new simulations | Architectural — LifecycleManager blocks transitions from retired |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Scenario System owns all scenario definitions exclusively; Engine references scenarios by ID |
| R2 — Dependency Order | Scenario System depends on the Scenario Store; no circular dependencies with Engine or Validation |
| R3 — DRY | Templates prevent repeated scenario definitions; variants capture only deltas from base |
| R4 — Builder Pattern | Scenario Builder handles construction, validation, and defaults; scenarios are complex objects |
| R9 — Deterministic | Versioning ensures reproducibility — a scenario ID + version always refers to the same definition |
| R10 — Simpler Over Complex | Single-domain single-criteria scenarios are the default; multi-domain and variants are opt-in |
| R14 — Paved Path | Creating a simple scenario with default parameters is the standard path |
| R15 — Open/Closed | New parameter types, constraints, and collection filters can be added without modifying the builder interface |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Simulation/000-Overview.md | System overview defining the role of scenarios in simulation |
| Bible/04-Execution/Simulation/001-Simulation-Engine.md | Engine consumes scenarios as input for execution |
| Bible/04-Execution/Simulation/003-Validation.md | Validation evaluates scenarios against success criteria |
| Bible/02-Core/Brain/Decision/000-Overview.md | Decision System proposes scenarios and consumes results |
| Bible/04-Execution/Workflow/000-Overview.md | WFE can create scenarios from workflow DAGs to simulate execution |
| Physics/010-Execution.md | Execution invariants — scenarios must be validated before simulation |
