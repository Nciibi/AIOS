# AIOS Bible â€” Interfaces
## Dashboard â€” 004: User Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-DB-004 |
| Source Laws | Law 4 â€” Law of Evidence, Law 8 â€” Law of Verification-First, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The User Management subsystem governs who can see what on the Dashboard, how they personalize their views, and how saved views and sharing work. It enforces permission-based access, isolates user preferences, and ensures all customization is built on top of the same evidence-backed data layer.

## Architecture

```
User Identity (authenticated viewer)
       |
       v
Permission Check (view access, action access)
       |
       v
View Access (which views the user can see)
       |
       v
Preference Application (theme, layout, defaults)
       |
       v
Customization (user-specific widget arrangement)
       |
       v
Save / Share (persist view state; share with others)
       |
       v
Display (rendered view with user context)
```

## Data Model

```typescript
interface DashboardUser {
  userId: string;
  identityRef: string;
  roles: string[];
  permissions: string[];
  preferences: UserPreference;
}

interface ViewPermission {
  viewId: string;
  userId: string;
  accessLevel: 'view' | 'drill' | 'configure' | 'share' | 'admin';
  grantedAt: Timestamp;
  grantedBy: string;
}

interface UserPreference {
  userId: string;
  theme: 'light' | 'dark' | 'system';
  defaultView: string;
  refreshInterval: number;
  widgetLayouts: Record<string, WidgetLayout>;
  notificationSettings: Record<string, boolean>;
  updatedAt: Timestamp;
}

interface SavedView {
  savedViewId: string;
  userId: string;
  name: string;
  description: string;
  baseViewId: string;
  widgets: WidgetConfig[];
  filters: Record<string, unknown>;
  layout: Record<string, WidgetLayout>;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

interface ViewShare {
  shareId: string;
  savedViewId: string;
  ownerId: string;
  targetUserId: string;
  accessLevel: 'view' | 'drill' | 'configure';
  expiresAt?: Timestamp;
  createdAt: Timestamp;
}

interface AccessControl {
  userId: string;
  resourceType: 'view' | 'widget' | 'metric' | 'alert';
  resourceId: string;
  permission: string;
  effect: 'allow' | 'deny';
}
```

## Core Concepts

### 1. Identity and Permissions

Every dashboard viewer has an identity with associated roles and permissions. Permissions are checked at the view level (which views are visible), widget level (which widgets can be seen), and action level (drill-down, configure, share).

### 2. User Preferences

Preferences are personal settings that do not affect other users. Theme, default landing view, refresh interval, and widget layout positions are stored per user. Preferences are applied at view render time.

### 3. Saved Views

Users can save customized dashboard states as SavedView objects. A saved view captures the base view, widget arrangement, filters, and layout. Saved views are private by default and can be shared with specific users.

### 4. View Sharing

Saved views can be shared with other users with specified access levels: view (read-only), drill (can drill down to evidence), configure (can rearrange widgets). Shares can be time-limited via expiresAt.

### 5. Customization

Users can customize widget layouts within their allowed views. Customization is purely visual â€” all data remains evidence-backed and permission-gated. Custom layouts are stored as UserPreference entries and do not alter the underlying view definition.

## Operations

| Operation | Description |
|-----------|-------------|
| set_preference(userId, preference) | Update user dashboard preferences |
| customize_view(userId, viewId, layout) | Rearrange widgets in a view for a user |
| save_view(userId, savedView) | Persist a customized view as a SavedView |
| share_view(ownerId, share) | Share a saved view with another user |
| check_permission(userId, resourceId, action) | Verify access permission for a resource |
| get_saved_views(userId) | List all saved views owned by a user |
| revoke_share(shareId) | Remove a view share |

## Internal Interfaces

```typescript
interface UserPreferenceStore {
  get(userId: string): Promise<UserPreference>;
  set(userId: string, preference: UserPreference): Promise<void>;
  reset(userId: string): Promise<void>;
}

interface PermissionEvaluator {
  check(userId: string, resourceId: string, action: string): Promise<boolean>;
  listPermissions(userId: string): Promise<ViewPermission[]>;
  grant(permission: ViewPermission): Promise<void>;
  revoke(viewId: string, userId: string): Promise<void>;
}

interface SavedViewManager {
  save(savedView: SavedView): Promise<string>;
  load(savedViewId: string): Promise<SavedView>;
  delete(savedViewId: string): Promise<void>;
  share(share: ViewShare): Promise<string>;
  listSharedWithUser(userId: string): Promise<ViewShare[]>;
}
```

## Events

| DASH.EventType |   Produced When | Fields |
|-------|--------|-------------|
| DASH.UserPreferenceUpdated |   userId, changedFields | User dashboard preferences changed |
| DASH.ViewCustomized |   userId, viewId, widgetCount | Widget layout customized for user |
| DASH.ViewSaved |   userId, savedViewId, baseViewId | Dashboard view saved as preset |
| DASH.ViewShared |   shareId, ownerId, targetUserId | Saved view shared with another user |
| DASH.PermissionChanged |   userId, viewId, accessLevel, effect | View permission granted or revoked |
| DASH.ViewSharedExpired |   shareId, targetUserId | Time-limited share expired |
| DASH.PreferenceReset |   userId | User preferences reset to defaults |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| DB_USER_PERMISSION_DENIED | User lacks required access level for resource | ERROR | Return access denied; log unauthorized attempt |
| DB_USER_VIEW_NOT_FOUND | Saved view ID does not exist for user | ERROR | Return not found; list available views |
| DB_USER_SHARE_TARGET_INVALID | Share target user ID does not exist | WARNING | Reject share; return valid user list |
| DB_USER_PREFERENCE_SAVE_FAILED | UserPreference persistence fails | ERROR | Return last known preferences; retry save |
| DB_USER_CUSTOMIZATION_EXCEEDS_BOUNDS | Widget layout exceeds view grid | WARNING | Clamp layout to grid; notify user |
| DB_USER_SHARE_EXPIRED | Attempt to access expired shared view | WARNING | Deny access; prompt owner to renew share |
| DB_USER_IDENTITY_MISMATCH | User identity does not match permission record | FATAL | Deny all access; escalate to security |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| DB-024 | All dashboard access is permission-based, never open | Architectural â€” PermissionEvaluator gates every resource |
| DB-025 | User preferences are isolated per user; no cross-user leakage | Architectural â€” UserPreferenceStore keys by userId |
| DB-026 | Customization is visual only; data remains evidence-backed | Architectural â€” customize_view changes layout, not data source |
| DB-027 | Saved views are private unless explicitly shared | Algorithmic â€” SavedViewManager enforces owner-only listing |
| DB-028 | Share access level never exceeds owner's own access level | Algorithmic â€” PermissionEvaluator enforces access level ceiling |
| DB-029 | Identity mismatch triggers full access denial and escalation | Constitutional â€” DB_USER_IDENTITY_MISMATCH escalates to security |


## Cross-Cutting Concerns

### Security

Dashboard operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Dashboard emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Dashboard instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Dashboard declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | User Management owns preferences and permissions; views own definitions |
| R2 - Dependency Order | Depends on Identity system; no circular deps |
| R3 - DRY | User preferences reference view IDs; view definitions are not duplicated |
| R4 - Builder Pattern | SavedView uses builder for widget composition and filter config |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | View definitions immutable; customization stored as user overlay |
| R9 - Deterministic | Same user + same saved view = same rendered output |
| R10 - Simpler Over Complex | Default view for all users; customization is opt-in per user |
| R13 - Design for Failure | Preference save failure returns last known state; never blank |
| R14 - Paved Path | Health view is default for all new users |
| R15 - Open/Closed | New preference types register via UserPreference extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Dashboard/000-Overview.md | Base dashboard architecture and view model |
| Bible/08-Interfaces/Dashboard/001-Metrics.md | Users see evidence-backed metrics via permission-gated views |
| Bible/08-Interfaces/Dashboard/002-Widgets.md | Users customize widget layouts in saved views |
| Bible/08-Interfaces/Dashboard/005-Alerts.md | Alert visibility is permission-gated per user |
| Bible/08-Interfaces/UI/000-Overview.md | UI applies user preferences during rendering |
| Bible/08-Interfaces/Console/000-Overview.md | Console shares user identity for permission checks |
| Bible/01-Governance/001-CLS.md | Constitutional limits on data access govern permissions |
| Bible/06-Services/ACF/000-Overview.md | ACF transports permission check requests |
| Physics/005-Events.md | Evidence invariants â€” all viewed data is evidence-backed |
| Physics/011-Design-DNA.md | Design DNA rules govern user management construction |
