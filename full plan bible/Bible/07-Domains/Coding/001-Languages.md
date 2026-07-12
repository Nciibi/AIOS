# AIOS Bible â€” Domains
## Coding â€” 001: Language Support Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-COD-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Language Support Registry manages the set of programming languages that AIOS Code Workers can generate, analyze, review, and build. It defines the toolchain requirements, runtime detection rules, and feature capabilities for each supported language. Every code operation across the Coding domain consults this registry to determine what a Worker can produce for a given language and environment.

This registry enables AIOS to abstract over language-specific details while maintaining deterministic output guarantees. Language profiles include compiler/interpreter paths, linting configurations, formatting rules, test frameworks, and build tool metadata. The registry is consulted at Worker instantiation time to validate that the target runtime is available in the BuildSandbox.

## Architecture

```
                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                â”‚     Language Support Registry     â”‚
                â”‚  (in-memory + persisted to Academy)â”‚
                â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                       â”‚            â”‚
              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
              â”‚ Language   â”‚  â”‚ Toolchain     â”‚
              â”‚ Profiles   â”‚  â”‚ Configurationsâ”‚
              â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                       â”‚              â”‚
              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”
              â”‚     BuildSandbox Detection      â”‚
              â”‚  (runtime version verification)  â”‚
              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

The registry is organized as a two-level hierarchy: language profiles define the abstract interface for a language, and toolchain configurations define concrete runtime bindings for a specific version and platform. Code Workers request a language profile at session start; the registry resolves the optimal toolchain configuration based on available runtimes and resource constraints.

## Data Model

```typescript
interface LanguageRegistry {
  languages: Map<string, LanguageProfile>
  defaultLanguage: string
  version: string
  lastUpdated: timestamp
}

interface LanguageProfile {
  languageId: string
  displayName: string
  fileExtensions: string[]
  mimeTypes: string[]
  toolchains: ToolchainConfig[]
  capabilities: LanguageCapability[]
  generationTemplates: GenerationTemplateRef[]
  lintingProfiles: LintingConfig[]
  formattingProfiles: FormattingConfig[]
  testFrameworks: TestFramework[]
  maxContextWindow: number
  supportedFrameworks: string[]
}

interface ToolchainConfig {
  toolchainId: string
  languageId: string
  runtimeType: RuntimeType
  version: string
  executablePath: string
  versionCommand: string
  envVariables: Record<string, string>
  capabilityBounds: ToolchainCapabilityBounds
  platformSupport: PlatformSpec[]
  verified: boolean
  lastVerifiedAt: timestamp
}

interface ToolchainCapabilityBounds {
  maxFileSize: number
  maxModuleCount: number
  maxMemoryMB: number
  maxExecutionSeconds: number
  maxNestingDepth: number
}

interface LanguageCapability {
  capabilityId: string
  description: string
  supportedLevel: SupportLevel
}

interface PlatformSpec {
  os: string
  arch: string
  minVersion: string
}

enum RuntimeType {
  Compiler = "compiler",
  Interpreter = "interpreter",
  VirtualMachine = "vm",
  Transpiler = "transpiler",
}

enum SupportLevel {
  Full = "full",
  Partial = "partial",
  Experimental = "experimental",
  Deprecated = "deprecated",
}
```

## Core Operations

| Operation | Precondition | Postcondition |
|-----------|-------------|---------------|
| register_language | Language profile is valid and complete | Language is added to registry; `Coding.LanguageRegistered` is emitted |
| unregister_language | No active Workers use the language | Language is removed from registry; dependent Workers are notified |
| detect_runtime | BuildSandbox is active | Runtime version is verified and returned; `Coding.ToolchainVerified` emitted |
| get_toolchain | Language is registered | Optimal toolchain configuration is returned with capability bounds |
| resolve_profile | Language and platform are specified | Resolved LanguageProfile with platform-matched toolchain is returned |
| verify_toolchain | Toolchain entry exists | Runtime is executed with version command; verified flag is updated |
| get_capabilities | Language is registered | LanguageCapability array for all supported features is returned |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| ILanguageRegistry | Language Support Registry | CodeWorker | ACF query |
| IToolchainDetector | BuildSandbox | Language Support Registry | Internal RPC |
| IProfileResolver | Language Support Registry | CodeReviewer | ACF query |
| ICapabilityQuery | Language Support Registry | Sou Planner | ACF query |

## Events

| COD.EventType |   Produced When | Fields |
|-----------|--------------|--------|
| COD.LanguageRegistered |   A new language is added to the registry | language_id, display_name, toolchain_count, support_level |
| COD.LanguageUnregistered |   A language is removed from the registry | language_id, reason, affected_worker_count |
| COD.ToolchainVerified |   A toolchain runtime is verified successfully | toolchain_id, language_id, version, platform, duration_ms |
| COD.ToolchainFailed |   Toolchain verification fails | toolchain_id, language_id, error_output, retry_count |
| COD.ProfileResolved |   A language profile is resolved for a Worker | worker_id, language_id, toolchain_id, capability_count |
| COD.RuntimeDetected |   Runtime is auto-detected in a BuildSandbox | sandbox_id, detected_runtimes, version_map |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COD_LNG_001 | Unsupported language requested | Error | Return supported language list; Worker falls back to default |
| COD_LNG_002 | Missing toolchain for registered language | Error | Emit `Coding.ToolchainFailed`; attempt auto-install or report unavailability |
| COD_LNG_003 | Toolchain version mismatch | Warning | Select best-matching version; log version discrepancy |
| COD_LNG_004 | Runtime detection timeout | Error | Retry with extended timeout (max 3 attempts); use cached detection |
| COD_LNG_005 | Platform not supported by toolchain | Error | Return platform compatibility matrix; select fallback toolchain |
| COD_LNG_006 | Language profile validation failure | Error | Reject registration with validation error details |
| COD_LNG_007 | Capability queried but not registered | Warning | Return empty capability set; log missing capability |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COD-LNG-I-001 | Every registered language has at least one toolchain configuration | Registry validation rejects languages without toolchains |
| COD-LNG-I-002 | Same language+toolchain combo always produces deterministic profile | Profile resolution is a pure function of language_id and platform |
| COD-LNG-I-003 | A toolchain cannot be registered without verification | Registry enforces verified flag before marking toolchain as active |
| COD-LNG-I-004 | Language IDs are globally unique across the registry | Registry enforces uniqueness constraint on language_id field |
| COD-LNG-I-005 | Deprecated languages remain resolvable for existing Workers | Registry retains deprecated profiles but blocks new Worker assignment |


## Cross-Cutting Concerns

### Security

Coding operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Coding emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Coding instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Coding declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Language registry is a single, focused module with no cross-cutting concerns |
| R2 - Dependency Order | Registry depends on BuildSandbox for detection; CodeWorker depends on Registry |
| R3 - DRY | Language profiles are defined once per language; toolchains inherit from profiles |
| R4 - Builder Pattern | Profile resolution uses builder pattern: profile + platform -> resolved config |
| R5 - Liskov Substitution | All language profiles implement same LanguageProfile interface |
| R6 - DI over Singletons | Registry is injected into Workers via ACF; not accessed as global singleton |
| R9 - Deterministic | Same language_id + platform + toolchain version always produces identical profile |
| R10 - Simpler Over Complex | Registry uses flat language map with no inheritance between language profiles |
| R13 - Design for Failure | Missing toolchain returns degraded profile; Workers operate in limited mode |
| R14 - Paved Path | Single paved path: register -> detect -> verify -> resolve -> use |
| R15 - Open/Closed | New languages can be added by registering new profiles; registry logic unchanged |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Coding/000-Overview.md | Coding domain overview â€” language registry is a foundational component |
| Bible/07-Domains/Coding/002-Code-Generation.md | Code Generation â€” consumes language profiles for generation templates |
| Bible/07-Domains/Coding/003-Review.md | Code Review â€” uses language capabilities to determine review scope |
| Bible/07-Domains/Coding/004-Refactoring.md | Refactoring â€” queries registry for language-specific symbol resolution |
| Physics/005-Events.md | Evidence â€” all registry changes are recorded as Events |
| Physics/007-Capabilities.md | Capabilities â€” toolchain capability bounds are enforced via Physics |
| Physics/010-Execution.md | Execution â€” toolchain verification is part of the execution authorization stage |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” CodeWorker Genomes reference language capabilities from registry |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” toolchain providers integrate through registry |
