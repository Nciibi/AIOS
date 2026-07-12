# AIOS Bible â€” Brain
## 003 â€” Voice Profile Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Voice |
| Document ID | AIOS-BBL-002-VCE-003 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Voice Profile Manager manages voice profile definitions that select which provider voice is used for TTS synthesis and which STT language defaults apply. Profiles are organized into four tiers: default system voice, user preference, context override, and custom (cloned/created) voices. Profiles map logical voice names to provider-specific voice IDs, support user scoping for multi-tenant deployments, and include metadata for usage tracking and fallback resolution.

Under VOI-005, voice profiles are scoped to the user who created them. Authorization is enforced at the API level.

## Data Model

### VoiceProfile

```typescript
VoiceProfile {
  profile_id: string                   // UUID
  name: string                         // User-facing display name
  voice_type: "default_system" | "user_preference" | "context_override" | "custom"
  provider: string                     // Provider identifier
  voice_name: string                   // Provider-specific voice ID
  language: string                     // BCP-47 language tag
  gender?: "male" | "female" | "neutral"
  description?: string
  sample_url?: string                  // URL to audio preview
  config_overrides?: {
    default_quality?: "high" | "standard" | "low"
    default_speed?: number
    default_pitch?: number
    default_volume?: number
    default_style?: "neutral" | "conversational" | "announcement"
  }
  scope: {
    user_id?: string                   // null for system-wide profiles
    session_id?: string                // For context_override type
    organization_id?: string
  }
  is_active: boolean
  metadata: {
    created_at: timestamp
    updated_at: timestamp
    usage_count: number
    last_used: timestamp
    source?: string                    // "predefined" | "clone" | "import" | "api"
    tags?: string[]
  }
}
```

### Profile Types

| Type | Scope | Persistence | Example |
|------|-------|-------------|---------|
| `default_system` | System-wide | Always present | "Sou Default" â€” English, female, neural |
| `user_preference` | Per-user | Persisted in Memory OS | "Alice prefers deep male voice" |
| `context_override` | Per-session | Ephemeral, cleared with session | "Announcement style for briefing mode" |
| `custom` | Per-user, user-created | Persisted in Memory OS | "Bob's cloned voice from sample" |

Default system profiles are read-only and cannot be deleted. They are seeded by the system on first install.

### ProfileProviderMapping

```typescript
ProfileProviderMapping {
  mapping_id: string
  profile_id: string
  provider: string
  provider_voice_id: string
  priority: number                   // 0â€“100, higher = preferred
  is_active: boolean
  capabilities?: {
    qualities: ("high" | "standard" | "low")[]
    styles: string[]
    languages: string[]
    max_text_length: number
  }
}
```

A profile can map to the same voice across multiple providers (for failover). The priority field determines which provider is selected when the primary is unavailable.

## Core Concepts

### Profile Resolution Order

When the TTS Engine requests a voice, profiles are resolved in this order:

```
1. Session-level context_override profile (if set)
2. User-level user_preference profile (if exists)
3. User-level custom profile (if marked as default)
4. default_system profile (always available)
```

Each tier cascades to the next if the profile is inactive, the provider is unavailable, or the language is unsupported.

### Profile CRUD

```typescript
createProfile(profile: CreateProfileRequest): Promise<VoiceProfile>
getProfile(profile_id: string): Promise<VoiceProfile | null>
listProfiles(filter?: ProfileFilter): Promise<VoiceProfile[]>
updateProfile(profile_id: string, updates: UpdateProfileRequest): Promise<VoiceProfile>
deleteProfile(profile_id: string): Promise<void>
setDefaultProfile(profile_id: string, user_id: string): Promise<void>
getDefaultProfile(user_id?: string): Promise<VoiceProfile>
```

#### Create

```typescript
CreateProfileRequest {
  name: string
  voice_type: "user_preference" | "context_override" | "custom"
  provider: string
  voice_name: string
  language: string
  gender?: "male" | "female" | "neutral"
  description?: string
  sample_url?: string
  config_overrides?: ConfigOverrides
  scope: { user_id: string, session_id?: string }
  metadata?: { tags?: string[] }
}
```

- System profiles are not creatable via API
- `context_override` profiles automatically expire when session ends
- `custom` profiles require provider SDK support for voice cloning

#### List

```typescript
ProfileFilter {
  user_id?: string
  voice_type?: VoiceProfileType
  provider?: string
  language?: string
  gender?: "male" | "female" | "neutral"
  is_active?: boolean
}
```

### Provider Mapping

Profiles are mapped to provider-specific voice IDs. A single profile may map to equivalent voices across multiple providers:

```typescript
addProviderMapping(profile_id: string, mapping: ProviderMappingInput): Promise<ProfileProviderMapping>
removeProviderMapping(mapping_id: string): Promise<void>
listProviderMappings(profile_id: string): Promise<ProfileProviderMapping[]>
```

Mapping ensures that if a provider is unavailable, the router can select a fallback provider with the closest equivalent voice.

### Default Voice Fallback

```typescript
getDefaultProfile(user_id?: string): Promise<VoiceProfile>
```

Resolution logic:

```
1. If user_id provided:
   a. Return user's default preference (if set and active)
   b. Return user's first custom profile (if any)
2. Return system default profile (always exists)
```

The system default profile is guaranteed to exist. If the default profile's provider is unhealthy, the Voice Router selects the next best active profile of the same type.

### Usage Tracking

Each `VoiceProfile` tracks usage metadata:

| Field | Updated When | Purpose |
|-------|-------------|---------|
| usage_count | Every TTS synthesis using this profile | Popularity ranking |
| last_used | Every TTS synthesis | Inactivity cleanup |
| updated_at | Profile edit, mapping change | Cache invalidation |

Usage data is used for:
- Sorting profiles by recency in UI lists
- Identifying unused profiles for archival
- Analytics on voice preference trends

## Internal Interface

```typescript
interface VoiceProfileManager {
  // CRUD
  createProfile(request: CreateProfileRequest): Promise<VoiceProfile>
  getProfile(profile_id: string): Promise<VoiceProfile | null>
  listProfiles(filter?: ProfileFilter): Promise<VoiceProfile[]>
  updateProfile(profile_id: string, updates: UpdateProfileRequest): Promise<VoiceProfile>
  deleteProfile(profile_id: string): Promise<void>

  // Default profile resolution
  getDefaultProfile(user_id?: string): Promise<VoiceProfile>
  setDefaultProfile(profile_id: string, user_id: string): Promise<VoiceProfile>

  // Provider mappings
  addProviderMapping(profile_id: string, mapping: ProviderMappingInput): Promise<ProfileProviderMapping>
  removeProviderMapping(mapping_id: string): Promise<void>
  listProviderMappings(profile_id: string): Promise<ProfileProviderMapping[]>
  resolveProfileForProvider(profile_id: string, provider: string): Promise<ProfileProviderMapping | null>

  // Profile availability
  getActiveProfilesForLanguage(language: string): Promise<VoiceProfile[]>
  getDefaultForLanguage(language: string, user_id?: string): Promise<VoiceProfile>

  // Lifecycle
  initializeDefaults(): Promise<void>
  cleanExpiredSessions(): Promise<number>    // Removes context_override profiles for ended sessions

  // Internal helpers
  incrementUsage(profile_id: string): Promise<void>
  validateProfile(profile: Partial<VoiceProfile>): ValidationResult
}

interface UpdateProfileRequest {
  name?: string
  provider?: string
  voice_name?: string
  language?: string
  gender?: "male" | "female" | "neutral"
  description?: string
  sample_url?: string
  config_overrides?: ConfigOverrides
  is_active?: boolean
  metadata?: { tags?: string[] }
}

interface ProviderMappingInput {
  provider: string
  provider_voice_id: string
  priority: number
  capabilities?: ProviderCapabilities
}

interface ProviderCapabilities {
  qualities: ("high" | "standard" | "low")[]
  styles: string[]
  languages: string[]
}

interface ValidationResult {
  valid: boolean
  errors: ValidationError[]
}

interface ValidationError {
  field: string
  code: string
  message: string
}

type ProfileType =
  | "default_system"
  | "user_preference"
  | "context_override"
  | "custom"

type ProfileErrorCode =
  | "VOI_PROFILE_NOT_FOUND"
  | "VOI_PROFILE_READ_ONLY"
  | "VOI_PROFILE_SCOPE_MISMATCH"
  | "VOI_PROFILE_LIMIT_EXCEEDED"
  | "VOI_PROFILE_NAME_EXISTS"
  | "VOI_PROVIDER_MAPPING_EXISTS"
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VCE.VoiceProfileCreated |     profile_id, name, voice_type, provider, user_id | New voice profile created |
| VCE.VoiceProfileUpdated |     profile_id, name, changed_fields | Profile properties modified |
| VCE.VoiceProfileDeleted |     profile_id, name, voice_type, provider | Profile removed |
| VCE.VoiceProfileDefaultSet |     profile_id, user_id | User default profile changed |
| VCE.VoiceProfileDefaultFallback |     profile_id, reason, fallback_profile_id | Default unavailable, fell back |
| VCE.VoiceProfileProviderMapped |     profile_id, mapping_id, provider, voice_id | New provider mapping added |
| VCE.VoiceProfileProviderUnmapped |     profile_id, mapping_id, provider | Provider mapping removed |
| VCE.VoiceProfileUsageIncremented |     profile_id, total_usage | Usage count updated |
| VCE.VoiceProfileSessionExpired |     profile_id, session_id | Context override profile cleaned |
| VCE.VoiceProfileLimitWarning |     user_id, current_count, max_allowed | User approaching custom profile limit |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VPM-001 | The system always has at least one active default profile | Seed â€” initialized on first install |
| VPM-002 | Default system profiles are read-only and cannot be deleted | API â€” delete fails with `VOI_PROFILE_READ_ONLY` |
| VPM-003 | Context override profiles expire when their session ends | Lifecycle â€” `cleanExpiredSessions()` called by Session Manager |
| VPM-004 | A user can have at most one active default preference | Algorithmic â€” `setDefaultProfile` replaces previous default |
| VPM-005 | Profiles are scoped to exactly one user unless system-wide | Schema â€” `scope.user_id` is required for non-system types |
| VPM-006 | Provider voice IDs are unique per provider within a mapping | Schema â€” unique constraint on (provider, provider_voice_id) |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Profile not found | `VOI_PROFILE_NOT_FOUND` | Return null; caller falls back to default |
| Attempt to delete a system profile | `VOI_PROFILE_READ_ONLY` | Return error; system profiles cannot be deleted |
| User exceeds max custom profiles (default: 20) | `VOI_PROFILE_LIMIT_EXCEEDED` | Return error; user must delete unused profiles |
| Profile name already exists for user | `VOI_PROFILE_NAME_EXISTS` | Return error; names must be unique per user |
| Provider mapping already exists for voice | `VOI_PROVIDER_MAPPING_EXISTS` | Return error; update existing mapping instead |
| Scope mismatch (e.g., user_id on a system profile) | `VOI_PROFILE_SCOPE_MISMATCH` | Return error; scope fields validated on create/update |
| Provider specified in profile does not exist | `VOI_PROVIDER_UNAVAILABLE` | Create profile with inactive flag; emit warning |
| Voice name not found in provider | `VOI_VOICE_NOT_FOUND` | Return error; list available voices for provider |


## Cross-Cutting Concerns

### Security

Voice System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Voice System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Voice System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Voice System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Voice Profile Manager handles only profile definitions and resolution |
| R2 â€” Dependency Order | Depends on Memory OS for persistence; no upward deps |
| R3 â€” DRY | Profile type behavior defined once in schemas |
| R4 â€” Builder Pattern | Profile built by Create â†’ Validate â†’ Store â†’ Index |
| R5 â€” Liskov Substitution | Any profile can be substituted for another of compatible type |
| R6 â€” DI over Singletons | Profile store and providers injected |
| R9 â€” Deterministic | Same profile query returns same resolution (non-system depends on persistence) |
| R10 â€” Simpler Over Complex | Four clear profile types with cascade resolution |
| R13 â€” Design for Failure | Default fallback chain always produces a voice |
| R14 â€” Paved Path | Profile resolution flows through `getDefaultProfile()` or `getProfile()` |
| R15 â€” Open/Closed | New profile types added by extending type enum, not modifying resolution core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Voice/000-Overview.md | Voice Profile Manager is a core Voice System component |
| Voice/001-STT-Engine.md | STT uses profiles for language defaults |
| Voice/002-TTS-Engine.md | TTS resolves voice selection through profiles |
| Voice/004-Streaming.md | Streaming uses profiles for voice configuration |
| Brain/Conversation/000-Overview.md | Conversation OS stores user voice preferences |
| Brain/Memory/000-Overview.md | Profile persistence and retrieval |
| Bible/04-Execution/Runtime/ | Profiles reference provider registrations |
