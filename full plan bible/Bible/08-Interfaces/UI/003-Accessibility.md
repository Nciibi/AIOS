# AIOS Bible â€” Interfaces
## UI â€” 003: Accessibility

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-UI-003 |
| Source Laws | Law 1 â€” Law of Origin, Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Accessibility system ensures every human interface in AIOS meets WCAG 2.1 AA compliance as a minimum, with AAA as the target for all core interaction paths. It enforces screen reader support, keyboard-only navigation, sufficient color contrast, predictable focus management, correct ARIA attribute usage, and continuous accessibility testing. Every human â€” regardless of ability â€” must be able to interact with AIOS through any channel.

## Architecture

```
Accessibility Audit (automated scan + manual review)
        |
        v
Remediation (violation fix, ARIA correction, contrast adjustment)
        |
        v
Validation (re-scan, regression check, pairwise review)
        |
        v
Monitoring (continuous CI/CD gate, usage telemetry)
        |
        v
Compliance Reporting (WCAG level score, exception log, roadmap)
```

Audit runs on every component registration and every production build. Remediation is gated â€” violations above threshold block deployment. Monitoring runs continuously in production, reporting real-time accessibility health.

## Data Model

```typescript
interface WCAGCheck {
  checkId: string;
  criteria: string;  // '1.1.1', '1.4.3', '2.1.1', '2.4.3', '3.3.2', '4.1.2'
  level: 'A' | 'AA' | 'AAA';
  description: string;
  passed: boolean;
  elements: string[];  // affected component IDs
}

interface AccessibilityViolation {
  violationId: string;
  checkId: string;
  componentId: string;
  severity: 'critical' | 'major' | 'minor';
  description: string;
  wcagCriteria: string;
  suggestedFix: string;
}

interface ScreenReaderConfig {
  configId: string;
  reader: 'NVDA' | 'JAWS' | 'VoiceOver' | 'TalkBack';
  version: string;
  liveRegion: 'off' | 'polite' | 'assertive';
  announceDynamicContent: boolean;
  testPatterns: string[];
}

interface KeyboardNavMap {
  mapId: string;
  componentId: string;
  order: number;
  shortcuts: Record<string, string>;  // key -> action
  tabStops: string[];
  focusTraps: string[];  // elements that trap focus
}

interface FocusOrder {
  orderId: string;
  componentId: string;
  elements: FocusElement[];
  isCircular: boolean;  // wraps around at end
}

interface ContrastRatio {
  foreground: string;  // token reference
  background: string;  // token reference
  ratio: number;  // calculated
  minimumAA: number;  // 4.5:1 normal, 3:1 large
  minimumAAA: number;  // 7:1 normal, 4.5:1 large
  passed: boolean;
}
```

## Core Concepts / Operations

| Operation | Description |
|-----------|-------------|
| audit_accessibility | Run full WCAG scan on component tree or page |
| remediate_violation | Apply fix for identified accessibility violation |
| configure_screen_reader | Set screen reader announcement behavior and test patterns |
| set_focus_order | Establish tab order and keyboard navigation map |
| verify_contrast | Compute and validate contrast ratio between foreground and background |

Audit produces a report of all WCAG checks. Remediation applies the suggested fix and re-audits. Focus order is computed from the component tree and must match visual reading order.

## Internal Interfaces

```typescript
interface AccessibilityAuditor {
  audit(componentId: string): Promise<WCAGCheck[]>;
  auditAll(): Promise<Map<string, WCAGCheck[]>>;
  report(): ComplianceReport;
}

interface ViolationManager {
  log(violation: AccessibilityViolation): Promise<void>;
  resolve(violationId: string, fix: string): Promise<void>;
  outstanding(severity?: string): AccessibilityViolation[];
}

interface ScreenReaderService {
  configure(config: ScreenReaderConfig): Promise<void>;
  announce(message: string, priority: string): Promise<void>;
  test(config: ScreenReaderConfig): Promise<TestResult>;
}

interface FocusManager {
  computeFocusOrder(tree: UIComponent[]): FocusOrder;
  setFocus(elementId: string): Promise<void>;
  trap(containerId: string): Promise<void>;
  release(): Promise<void>;
}

interface ContrastValidator {
  validate(token: DesignToken): ContrastRatio;
  validateAll(tokens: DesignToken[]): ContrastRatio[];
  suggestAdjustment(token: DesignToken, target: number): string;
}
```

## Events

| UI.EventType |      Produced When | Fields |
|-------|--------|-------------|
| UI.AccessibilityAuditRun |      auditId, componentCount, passedCount, failedCount | Full accessibility scan completed |
| UI.ViolationDetected |      violationId, componentId, severity, wcagCriteria | New accessibility violation found |
| UI.ViolationRemediated |      violationId, componentId, fixApplied | Violation resolved and re-audited |
| UI.ComplianceReportGenerated |      reportId, aaPassRate, aaaPassRate | Compliance report published |
| UI.FocusOrderChanged |      componentId, previousOrder, newOrder | Keyboard navigation order modified |
| UI.ScreenReaderConfigured |      configId, reader, version | Screen reader settings updated |
| UI.ContrastFailure |      tokenId, ratio, minimumRequired | Token pair fails contrast check |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| A11Y_THRESHOLD_EXCEEDED | Violations exceed deployment threshold (AA: 0 critical) | Error | Block build; require remediation |
| A11Y_SCREEN_READER_INCOMPAT | Component behavior incompatible with screen reader | Warning | Log incompatibility; suggest ARIA fix |
| A11Y_FOCUS_TRAP | Focus enters element and cannot exit via keyboard | Error | Block render; implement escape handler |
| A11Y_CONTRAST_FAILURE | Contrast ratio below WCAG AA minimum | Error | Block token registration; suggest adjustment |
| A11Y_MISSING_LABEL | Interactive element lacks accessible label | Warning | Auto-generate from context; flag for review |
| A11Y_KEYBOARD_GAP | Navigation path not reachable via keyboard alone | Error | Reject component; enforce tabIndex ordering |
| A11Y_LIVE_REGION_MISSING | Dynamic content change not announced | Warning | Add polite live region; log for audit |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| A11Y-001 | Every interactive element is reachable via keyboard only | Algorithmic â€” Focus Manager validates tabIndex chain |
| A11Y-002 | Focus indicator is always visible with 3:1 contrast minimum | Algorithmic â€” AccessibilityAuditor checks focus styles |
| A11Y-003 | All non-text content has a text alternative (WCAG 1.1.1) | Algorithmic â€” screen reader test validates all alt attributes |
| A11Y-004 | Color is never the sole means of conveying information | Algorithmic â€” AccessibilityAuditor flags color-only states |
| A11Y-005 | All touch targets are at least 44x44 CSS pixels | Algorithmic â€” LayoutEngine measures and validates targets |
| A11Y-006 | Error suggestions are programmatically associated with inputs | Algorithmic â€” ARIA describedBy required on error state |


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
| R1 - Modulsingularity | Accessibility is a first-class concern owned by this system; no component bypasses it |
| R2 - Dependency Order | Depends on Components (002), Design System (001); no cycles |
| R3 - DRY | WCAG criteria defined once; referenced by all audit checks |
| R4 - Builder Pattern | Violation remediation built stepwise with audit at each stage |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | A11Y concerns encapsulated within AccessibilityEngine; components opt in via props |
| R9 - Deterministic | Same component + same audit = same violation set |
| R10 - Simpler Over Complex | AA compliance is default; AAA is opt-in per component |
| R13 - Design for Failure | Screen reader failure degrades to visible text; never silent |
| R14 - Paved Path | Use predefined focus order; custom ordering requires explicit override |
| R15 - Open/Closed | New WCAG criteria registered via new check definitions; existing checks immutable |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/UI/000-Overview.md | Base UI document defines channels that must all be accessible |
| Bible/08-Interfaces/UI/001-Design-System.md | Design token contrast ratios validated by this system |
| Bible/08-Interfaces/UI/002-Components.md | Every component registered must pass accessibility audit |
| Bible/08-Interfaces/UI/004-Themes.md | Theme token overrides re-validated for contrast compliance |
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console enforces accessibility on critical actions |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard data visualizations must pass WCAG color checks |
| Bible/02-Core/Brain/Conversation/000-Overview.md | Conversational channel supports screen reader announcement |
