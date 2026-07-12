# AIOS Bible â€” Interfaces
## UI â€” 002: Components

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-UI-002 |
| Source Laws | Law 1 â€” Law of Origin, Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The interactive component library provides reusable UI controls for all human interface channels: form controls for command input, data display for visualization, navigation for session routing, feedback indicators for notifications, input components for the conversational channel, and composite widgets for approval workflows. Every component integrates with the Interface Hub and Intent Parser from the base UI document.

## Architecture

```
Component Tree (hierarchy: page > section > widget > control)
        |
        v
State Management (local state, session state, derived state)
        |
        v
Event Handling (click, keydown, submit, focus, blur)
        |
        v
Rendering (virtual DOM diffing, lazy hydration, animation)
        |
        v
Accessibility (ARIA attributes, focus order, screen reader labels)
        |
        v
Testing (unit, integration, visual regression, accessibility audit)
```

Components are composed from the design system atoms (buttons, inputs, labels) into molecules (form groups, data rows) into organisms (data tables, approval panels) into templates (command view, notification center).

## Data Model

```typescript
interface UIComponent {
  componentId: string;
  type: 'form' | 'display' | 'navigation' | 'feedback' | 'input' | 'composite';
  specRef: string;  // ComponentSpec.componentId from design system
  parentId?: string;
  children: string[];
  state: ComponentState;
  eventHandlers: EventHandler[];
  renderConfig: RenderConfig;
  accessibility: AccessibilityProps;
}

interface ComponentState {
  componentId: string;
  status: 'idle' | 'loading' | 'error' | 'success' | 'disabled';
  value: unknown;
  errors: Record<string, string>;
  dirty: boolean;
  lastInteraction: Timestamp;
}

interface EventHandler {
  event: string;  // 'click', 'change', 'submit', 'keydown', 'focus'
  handlerType: 'local' | 'dispatch' | 'acf';
  action: string;  // function or message to send
  debounceMs?: number;
}

interface RenderConfig {
  template: string;
  hydration: 'eager' | 'lazy' | 'progressive';
  animation: 'none' | 'fade' | 'slide' | 'instant';
  virtual: boolean;  // virtual DOM node
  priority: 'critical' | 'normal' | 'deferred';
}

interface AccessibilityProps {
  role: string;
  label: string;
  describedBy?: string;
  tabIndex: number;
  keyboardShortcut?: string;
  liveRegion?: 'off' | 'polite' | 'assertive';
}
```

## Core Concepts / Operations

| Operation | Description |
|-----------|-------------|
| render_component | Mount component tree with resolved state and configuration |
| handle_event | Process user interaction through event handler chain |
| manage_state | Update component state with immutability guarantee |
| apply_accessibility | Attach ARIA attributes and focus management to rendered tree |
| test_component | Run component through unit, visual, and accessibility test suites |

Render computes a virtual DOM diff, applies only changed nodes. Events bubble through the handler chain from child to parent. State transitions are immutable â€” each update produces a new state snapshot.

## Internal Interfaces

```typescript
interface ComponentRegistry {
  register(component: UIComponent): Promise<void>;
  get(componentId: string): UIComponent;
  findParent(childId: string): UIComponent | null;
  query(type: string, status: string): UIComponent[];
}

interface StateManager {
  getState(componentId: string): ComponentState;
  setState(componentId: string, patch: Partial<ComponentState>): Promise<void>;
  subscribe(componentId: string, listener: StateListener): Unsubscribe;
  snapshot(): Map<string, ComponentState>;
}

interface EventBus {
  emit(eventId: string, payload: unknown): Promise<void>;
  on(eventId: string, handler: EventHandler): Unsubscribe;
  dispatchToACF(sessionId: string, message: HumanMessage): Promise<void>;
}

interface RenderEngine {
  mount(spec: RenderConfig, container: DOMNode): Promise<void>;
  patch(diff: VDomDiff): Promise<void>;
  unmount(componentId: string): Promise<void>;
}

interface AccessibilityEngine {
  apply(props: AccessibilityProps, node: DOMNode): Promise<void>;
  validate(node: DOMNode): AccessibilityViolation[];
  focusOrder(tree: UIComponent[]): FocusOrder;
}
```

## Events

| UI.EventType |    Produced When | Fields |
|-------|--------|-------------|
| UI.ComponentRendered |    componentId, type, timestamp | Component mounted and visible |
| UI.ComponentInteracted |    componentId, event, value | User interaction on component |
| UI.StateChanged |    componentId, previousState, newState | Immutable state transition |
| UI.AccessibilityApplied |    componentId, role, label | ARIA attributes attached |
| UI.EventBubbled |    componentId, event, origin, target | Event propagated through handler chain |
| UI.RenderPatched |    componentId, diffSize, duration | Virtual DOM patch applied |
| UI.ComponentTested |    componentId, testType, result | Test suite execution completed |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| COMP_RENDER_FAILURE | Component template fails to compile | Error | Fall back to plain text representation |
| COMP_EVENT_LOOP_OVERFLOW | Event handler exceeds 500ms execution | Warning | Async offload; log handler for profiling |
| COMP_STATE_INCONSISTENCY | State mutation detected (not immutable) | Error | Revert state to last snapshot; log violation |
| COMP_ACCESSIBILITY_VIOLATION | Component fails WCAG check | Warning | Block production deploy; allow dev render |
| COMP_HYDRATION_MISMATCH | Server and client render differ | Error | Use server render; log mismatch details |
| COMP_UNKNOWN_COMPONENT | componentId not in registry | Error | Render placeholder; register component |
| COMP_EVENT_UNBOUND | Event triggered with no handler | Info | No-op; log for dead code detection |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COMP-001 | Every component renders deterministically from the same state | Algorithmic â€” render engine validates output identity |
| COMP-002 | All state transitions produce an immutable snapshot | Algorithmic â€” State Manager freezes state on set |
| COMP-003 | Every interactive component supports keyboard navigation | Algorithmic â€” Accessibility Engine validates tabIndex |
| COMP-004 | Events bubble from child to parent; never skip a level | Architectural â€” Event Bus enforces strict hierarchy |
| COMP-005 | Components reference registered design system specs only | Algorithmic â€” ComponentRegistry validates specRef |
| COMP-006 | Lazy-hydrated components render placeholder synchronously | Architectural â€” Render Engine guarantees fallback |


## Cross-Cutting Concerns

### Security

UI operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), UI emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), UI instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), UI declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Components are the exclusive atomic unit of UI rendering |
| R2 - Dependency Order | Depends on Design System (001), Interface Hub, Intent Parser; no cycles |
| R3 - DRY | Component logic defined once; reused via composition, not inheritance |
| R4 - Builder Pattern | Components built via ComponentFactory with validation |
| R5 - Liskov Substitution | Components interact only with their direct children and own state |
| R6 - DI over Singletons | Component internals hidden; interface via props, events, slots |
| R9 - Deterministic | Same props + same state = same render output every time |
| R10 - Simpler Over Complex | Prefer atoms over molecules; compose up only when necessary |
| R13 - Design for Failure | Render failure degrades to plain text, never blank screen |
| R14 - Paved Path | Default event handling via Event Bus; custom handlers are explicit opt-in |
| R15 - Open/Closed | New component types register via ComponentRegistry; existing types closed |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/UI/000-Overview.md | Base UI document â€” Interface Hub and IntentParser that components integrate with |
| Bible/08-Interfaces/UI/001-Design-System.md | Design system defines tokens and specs that components are built from |
| Bible/08-Interfaces/UI/003-Accessibility.md | Accessibility engine validates every component on render |
| Bible/08-Interfaces/UI/004-Themes.md | Theme system provides token overrides components consume |
| Bible/08-Interfaces/Console/000-Overview.md | Console uses same component library for governance interfaces |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard visualizations built from display-type components |
| Bible/06-Services/ACF/000-Overview.md | Component events dispatched to ACF for evidence recording |
