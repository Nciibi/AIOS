# AIOS Bible — Interfaces
## UI — 004: Themes

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-UI-004 |
| Source Laws | Law 1 — Law of Origin, Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Theme system provides light, dark, high-contrast, and custom theme support across all AIOS human interface surfaces. It manages theme definition as token overrides, dynamic switching without page reload, user preference persistence, theme inheritance for brand customization, and automatic preference detection via system settings. Every theme guarantees complete token coverage so no UI element is left un-styled.

## Architecture

```
Base Theme (canonical token set, all values defined)
        |
        v
Token Map (category -> name -> value lookup table)
        |
        v
Variant Override (light: overrides base; dark: overrides base)
        |
        v
Dynamic Switching (CSS custom properties, runtime swap)
        |
        v
Persistence (localStorage, server-side profile, preference API)
        |
        v
Inheritance Chain (base < variant < brand < user override)
```

Each layer in the inheritance chain overrides the previous. A user override takes highest precedence. Every theme variant must define values for every token in the base theme.

## Data Model

```typescript
interface ThemeDefinition {
  themeId: string;
  name: string;  // 'light', 'dark', 'high-contrast', 'custom'
  variant: ThemeVariant;
  tokens: ThemeToken[];
  baseThemeId: string;  // theme this derives from
  metadata: {
    author: string;
    version: string;
    created: Timestamp;
    tags: string[];
  };
}

interface ThemeToken {
  tokenId: string;
  name: string;  // matches DesignToken.name
  value: string;
  category: 'color' | 'typography' | 'spacing' | 'shadow' | 'easing';
  overrides: Record<string, string>;  // conditional overrides
}

interface ThemeVariant {
  variantId: string;
  type: 'base' | 'light' | 'dark' | 'high-contrast' | 'custom';
  parentVariantId?: string;
  colorScheme: 'light' | 'dark' | 'auto';
  contrast: 'normal' | 'high';
}

interface SwitchConfig {
  strategy: 'instant' | 'fade' | 'transition';
  durationMs: number;
  persistPreference: boolean;
  respectSystemSettings: boolean;
  fallbackThemeId: string;
}

interface ThemePreference {
  humanId: string;
  themeId: string;
  switchedAt: Timestamp;
  source: 'system' | 'manual' | 'auto';
  persist: boolean;
}

interface InheritanceChain {
  chainId: string;
  themeId: string;
  resolved: ThemeToken[];  // fully resolved token values after inheritance
  layers: {
    layer: string;  // 'base', 'variant', 'brand', 'user'
    themeId: string;
    tokens: string[];  // token IDs overridden at this layer
  }[];
}
```

## Core Concepts / Operations

| Operation | Description |
|-----------|-------------|
| define_theme | Register a new theme variant with token overrides |
| apply_theme | Set active theme and resolve inheritance chain |
| switch_theme | Transition from current theme to target theme |
| persist_preference | Save theme choice to human profile and client storage |
| inherit_theme | Compute resolved token map through inheritance chain |

Define validates complete token coverage and no unresolvable inheritance cycles. Apply resolves all tokens through the chain and swaps CSS custom properties. Switch uses the configured strategy (instant, fade, transition) to avoid visual flicker.

## Internal Interfaces

```typescript
interface ThemeRegistry {
  register(theme: ThemeDefinition): Promise<void>;
  get(themeId: string): ThemeDefinition;
  list(): ThemeDefinition[];
  resolve(themeId: string): InheritanceChain;
}

interface ThemeApplier {
  apply(themeId: string): Promise<void>;
  preview(themeId: string): Promise<ThemeToken[]>;
  rollback(): Promise<void>;
}

interface SwitchEngine {
  switch(targetThemeId: string, config: SwitchConfig): Promise<void>;
  detectSystemPreference(): 'light' | 'dark';
  computeTransition(current: ThemeToken[], target: ThemeToken[]): TokenDiff[];
}

interface PreferenceStore {
  save(preference: ThemePreference): Promise<void>;
  load(humanId: string): ThemePreference | null;
  clear(humanId: string): Promise<void>;
}

interface InheritanceResolver {
  compute(themeId: string): InheritanceChain;
  detectCycle(themeId: string): boolean;
  resolveToken(tokenName: string, chain: InheritanceChain): ThemeToken;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| UI.ThemeDefined | themeId, name, variant, baseThemeId | New theme variant registered |
| UI.ThemeApplied | themeId, resolvedTokens, duration | Theme activated and tokens applied |
| UI.ThemeSwitched | fromThemeId, toThemeId, strategy | Theme transition completed |
| UI.PreferencePersisted | humanId, themeId, source | User theme choice saved |
| UI.TokenMissingInTheme | themeId, tokenName, fallbackValue | Token not defined in theme; falling back to base |
| UI.InheritanceResolved | themeId, layers, totalTokens | Inheritance chain computed successfully |
| UI.ThemeRolledBack | themeId, previousThemeId, reason | Theme application failed; rolled back |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| THEME_TOKEN_MISSING | Theme variant does not define a required base token | Error | Block registration; list missing tokens |
| THEME_VARIANT_CONFLICT | Two variants share the same name and priority | Error | Reject registration; require unique name |
| THEME_SWITCH_FLICKER | Visual flash detected during theme transition | Warning | Fall back to instant swap; tune transition timing |
| THEME_PERSISTENCE_FAILURE | Preference write to client storage fails | Warning | Continue with current theme; retry on next load |
| THEME_INHERITANCE_CYCLE | Inheritance chain contains a loop | Error | Block resolve; report cycle path |
| THEME_UNKNOWN_VARIANT | Theme references undefined base variant | Error | Reject registration; require valid base variant |
| THEME_CONTRAST_DEGRADED | Theme token values produce contrast ratio below AA | Warning | Log degraded tokens; suggest dark/light corrections |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| THEME-001 | Every theme defines a value for every token in the base theme | Algorithmic — TokenRegistry validates complete coverage |
| THEME-002 | Theme switching completes within 100ms to prevent visual flicker | Architectural — SwitchEngine enforces timing budget |
| THEME-003 | User theme preference survives browser restart and session change | Algorithmic — PreferenceStore persists to both localStorage and profile |
| THEME-004 | Inheritance chains are acyclic | Algorithmic — InheritanceResolver detects and rejects cycles |
| THEME-005 | High-contrast theme overrides all color tokens to pass WCAG AAA | Algorithmic — ContrastValidator audits all tokens on registration |
| THEME-006 | System preference detection runs before any manual theme is applied | Architectural — SwitchEngine queries prefers-color-scheme on init |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Theme system exclusively manages visual presentation; no component defines its own colors |
| R2 — Dependency Order | Depends on Design System (001), Accessibility (003); no cycles |
| R3 — DRY | Token values defined once per theme; reused across all components |
| R4 — Builder Pattern | Theme variants built via inheritance chain with validation |
| R5 — Law of Demeter | Components interact only with resolved tokens; never with theme definitions |
| R6 — Encapsulation | Theme internals (inheritance, resolution) hidden behind ThemeApplier interface |
| R9 — Deterministic | Same theme + same tokens = same visual output every time |
| R10 — Simpler Over Complex | Light/dark are built-in; custom themes explicitly opt-in |
| R13 — Design for Failure | Missing token falls back to base theme; never leaves element un-styled |
| R14 — Paved Path | Light theme is default; dark and high-contrast are predefined variants |
| R15 — Open/Closed | New variants registered via ThemeRegistry; base theme closed for modification |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/UI/000-Overview.md | Base UI document defines channels that consume theme tokens |
| Bible/08-Interfaces/UI/001-Design-System.md | Design system defines the token schema that themes override |
| Bible/08-Interfaces/UI/002-Components.md | Components consume resolved tokens from active theme |
| Bible/08-Interfaces/UI/003-Accessibility.md | High-contrast theme must pass WCAG AAA validation |
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console respects theme but enforces high-contrast for critical UI |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboards inherit theme; data viz palettes come from theme tokens |
| Bible/05-Platform/004-EVS.md | Theme preference changes recorded as evidence for audit trail |
