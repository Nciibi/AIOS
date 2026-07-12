# AIOS Bible â€” Domains
## Communication â€” 003: Collaboration

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-COM-003 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Collaboration enables multi-user interaction within AIOS â€” shared sessions, workspace management, presence detection, typing indicators, concurrent state editing, and session handoff between Workers. It extends the Communication domain from one-to-one chat to many-to-many collaborative environments where human users and AIOS Workers share a common workspace, observe each other's presence, and synchronize state in near real time.

A CollaborationSession represents a shared context that persists across participant join and leave events. Participants include both human users (authenticated via IDS) and AIOS Workers (SupportAgent, ChatWorker). Presence tracking broadcasts live status changes â€” online, idle, focusing, typing. Workspace state is synchronized through ordered SyncEvent messages that each participant applies to their local replica, ensuring eventual consistency without requiring a central state store for every interaction.

## Architecture

```
Session lifecycle:
+-------------------+     +-------------------+     +-------------------+
| Session Created   | --> | Participant Join  | --> | Active Session    |
| (create_session)  |     | (join_session)    |     | broadcast_state   |
+-------------------+     +-------------------+     +-------------------+
                                                          |
                                                          v
+-------------------+     +-------------------+     +-------------------+
| Session Teardown  | <-- | Participant Leave | <-- | State Sync Loop   |
| (archive_session) |     | (leave_session)   |     | sync_event stream |
+-------------------+     +-------------------+     +-------------------+

State synchronization flow per participant:
+---------------------+
| Local Replica       |  Participant's view of shared state
| (workspace_state)   |
+----------+----------+
           |
           v
+---------------------+
| Outbox              |  Local mutations queued for broadcast
| (pending_events)    |
+----------+----------+
           |
           v
+---------------------+
| Event Broadcast     |  Ordered SyncEvent sent to all participants
| (broadcast_state)   |
+----------+----------+
           |
           v
+---------------------+
| Remote Replica      |  Other participants apply event and merge
| (apply_sync_event)  |
+---------------------+
```

Each participant maintains an independent local replica. Mutations are broadcast as SyncEvents with a vector clock for conflict detection. On conflict, the last-writer-wins strategy is applied with a divergence boundary check â€” if clock skew exceeds the threshold, a full state resync is triggered.

## Data Model

```typescript
interface CollaborationSession {
  sessionId: string;
  name: string;
  workspaceId: string;
  participants: Participant[];
  state: WorkspaceState;
  presenceMap: Map<string, PresenceState>;
  eventLog: SyncEvent[];
  createdAt: number;
  lastActivityAt: number;
  maxParticipants: number;
  metadata: Record<string, string>;
  sessionToken: string;
}

interface Participant {
  participantId: string;
  identityId: string;
  type: 'human' | 'worker';
  role: ParticipantRole;
  joinedAt: number;
  lastActiveAt: number;
  presence: PresenceState;
  connectionId: string;
  metadata: Record<string, string>;
}

interface PresenceState {
  status: 'online' | 'idle' | 'focusing' | 'away' | 'offline';
  typing: boolean;
  typingTarget?: string;
  currentFocus?: string;
  lastSeenAt: number;
  clientInfo: ClientInfo;
}

interface WorkspaceState {
  workspaceId: string;
  version: number;
  snapshot: unknown;
  lastMutatedAt: number;
  lastMutationBy: string;
}

interface SyncEvent {
  eventId: string;
  sessionId: string;
  senderId: string;
  eventType: SyncEventType;
  payload: unknown;
  vectorClock: Record<string, number>;
  timestamp: number;
  sequenceNumber: number;
  parentEventId?: string;
}

interface SessionHandoff {
  handoffId: string;
  sessionId: string;
  fromWorkerId: string;
  toWorkerId: string;
  stateSnapshot: WorkspaceState;
  pendingEvents: SyncEvent[];
  handoffToken: string;
  completedAt?: number;
  timeoutMs: number;
}

interface ClientInfo {
  clientType: string;
  clientVersion: string;
  platform: string;
  capabilities: string[];
}

type ParticipantRole = 'owner' | 'admin' | 'editor' | 'viewer' | 'watcher';
type SyncEventType = 'state_mutation' | 'cursor_move' | 'typing_indicator' | 'presence_change'
  | 'participant_join' | 'participant_leave' | 'handoff_initiated' | 'handoff_completed'
  | 'full_state_resync' | 'ping';

interface SessionPolicy {
  maxIdleMinutes: number;
  maxSessionHours: number;
  allowAnonymousViewers: boolean;
  requireApprovalForJoin: boolean;
  syncIntervalMs: number;
  divergenceThresholdMs: number;
}
```

## Core Concepts / Operations

| Operation | Preconditions | Postconditions |
|-----------|--------------|----------------|
| create_session | Creator authenticated, workspace exists | Session created with creator as owner participant; `Comm.SessionCreated` emitted |
| join_session | Participant authenticated, session active | Participant added to session; full current state sent; `Comm.ParticipantJoined` emitted |
| leave_session | Participant in session | Participant removed; presence updated; remaining participants notified |
| broadcast_state | SyncEvent produced by participant | Event sequenced, broadcast to all other participants; `Comm.StateSynced` emitted |
| detect_presence | Participant connection active | PresenceState updated; heartbeat monitored; `Comm.PresenceUpdated` emitted on change |
| handoff_session | Source Worker active, target Worker available | Session state transferred; pending events forwarded; target takes over as active Worker |
| resolve_conflict | Divergent SyncEvents detected | Last-writer-wins applied; divergence measured; full resync triggered if threshold exceeded |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| ISessionManager | Collaboration Module | ChatWorker, SupportAgent | ACF sync |
| IPresenceService | Collaboration Module | All participants | ACF event |
| ISyncEngine | Collaboration Module | ISessionManager | Internal |
| IHandoffCoordinator | Collaboration Module | Sou Planner | ACF query |
| IStateReplica | Collaboration Module | Participants (client-side) | ACF stream |

## Events

| COM.EventType |  Produced When | Fields |
|-----------|--------------|--------|
| COM.SessionCreated |  New collaboration session is created | session_id, workspace_id, creator_id, max_participants, created_at |
| COM.ParticipantJoined |  Participant enters an active session | session_id, participant_id, participant_type, role, current_participant_count |
| COM.ParticipantLeft |  Participant leaves or is removed from session | session_id, participant_id, reason, duration_ms, remaining_count |
| COM.StateSynced |  SyncEvent is broadcast to all participants | session_id, event_id, sender_id, event_type, sequence_number, vector_clock |
| COM.PresenceUpdated |  Participant presence status changes | session_id, participant_id, old_status, new_status, typing_state, last_seen_at |
| COM.SessionHandedOff |  Worker session is handed off to another Worker | session_id, from_worker, to_worker, state_version, pending_event_count, handoff_duration_ms |
| COM.StateDivergenceDetected |  Vector clock skew exceeds threshold | session_id, participant_ids, clock_diff_ms, threshold_ms, resync_initiated |
| COM.SessionArchived |  Session is closed and archived | session_id, duration_minutes, total_participants, total_events, reason |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COM-COL-001 | Session at maximum participant capacity | Error | Reject join with session_full reason; offer to create sub-session or wait-list |
| COM-COL-002 | Participant authentication failure â€” invalid token | Critical | Reject join; emit auth failure event; log identity for Security Council |
| COM-COL-003 | Sync conflict â€” concurrent mutations with divergent vector clocks | Warning | Apply last-writer-wins; log conflict; resync if divergence exceeds threshold |
| COM-COL-004 | Session handoff timeout â€” target Worker not ready | Error | Abort handoff; reinstate source Worker; emit handoff_timeout; retry with backoff |
| COM-COL-005 | State divergence beyond recovery threshold | Critical | Trigger full state resync from authoritative snapshot; all participants reload |
| COM-COL-006 | Presence heartbeat timeout â€” participant presumed disconnected | Warning | Mark presence as away; start idle timer; retain session slot for grace period |
| COM-COL-007 | Unsupported participant role requested | Error | Assign default viewer role; log role escalation attempt for audit |
| COM-COL-008 | SyncEvent sequence gap detected â€” missing intermediate events | Error | Request missing events from sender; if unavailable, trigger partial state resync |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COM-COL-I-001 | Every participant has a complete and consistent view of session state | SyncEngine sends full state snapshot on join; resync restores consistency on divergence |
| COM-COL-I-002 | SyncEvents are strictly ordered per session by sequence number | Event sequencing enforces monotonic sequence_number; gaps trigger recovery |
| COM-COL-I-003 | Every participant is authenticated before session access | Join operation validates identity token against IDS; anonymous sessions require policy override |
| COM-COL-I-004 | Session state is never lost on participant departure | WorkspaceState is retained in session until session archival; departure is soft event |
| COM-COL-I-005 | Handoff transfers complete session state including pending events | HandoffCoordinator serializes state snapshot plus unprocessed event queue before transfer |
| COM-COL-I-006 | Presence updates are eventually consistent across all participants | Presence broadcast converges within syncIntervalMs; stale presence is tolerated temporarily |


## Cross-Cutting Concerns

### Security

Communication operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Communication emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Communication instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Communication declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 (Modulsingularity) | Session management, presence, sync, and handoff are separate modules with well-defined interfaces |
| R2 (Capsule) | Each SyncEvent is a sealed capsule with immutable vector clock, sequence, and payload |
| R3 (DRY) | Workspace state is authored in one replica; SyncEvents are the single source of truth for mutations |
| R4 (Builder) | Session state is built incrementally by applying ordered SyncEvents to a base snapshot |
| R5 (Liskov Substitution) | All participant types (human, worker) implement the same IParticipant interface in session |
| R6 (DI over Singletons) | Session stores and sync engines are injected; no global session registry pattern |
| R9 (Deterministic) | Same ordered SyncEvent sequence applied to same initial state yields identical final state |
| R10 (Simpler Over Complex) | Conflict resolution is last-writer-wins; no multi-version merge or CRDT complexity |
| R13 (Design for Failure) | State divergence triggers automatic resync; no silent inconsistency persists |
| R14 (Paved Path) | Single paved path: create -> join -> sync -> handoff/leave -> archive; all deviations logged |
| R15 (Open/Closed) | New sync event types added without changing sync engine; new participant roles extend existing interface |

| R1 | Compliant |
| R2 | Compliant |
| R3 | Compliant |
| R4 | Compliant |
| R5 | Compliant |
| R6 | Compliant |
| R9 | Compliant |
| R10 | Compliant |
| R13 | Compliant |
| R14 | Compliant |
| R15 | Compliant |
## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Communication/000-Overview.md | Overview â€” Collaboration extends communication from one-to-one to many-to-many |
| Bible/07-Domains/Communication/001-Protocols.md | Upstream â€” Collaboration uses protocol negotiation for participant sync channels |
| Bible/07-Domains/Communication/002-Messaging.md | Downstream â€” Collaboration participant messages flow through messaging for delivery |
| Bible/06-Services/ACF/004-Subscriptions.md | Subscriptions â€” Presence and sync events use ACF subscription model for real-time broadcast |
| Bible/06-Services/ACF/005-Streaming.md | Streaming â€” SyncEvent stream uses ACF streaming for ordered event delivery |
| Physics/005-Events.md | Evidence â€” All session lifecycle and sync operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” Session size, sync frequency, and state complexity are bounded by capability profiles |
| Physics/009-Interaction.md | Interaction â€” Collaboration implements multi-participant human-AIOS interaction patterns |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning â€” Sou provides session handoff decisions and conflict resolution guidance |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” ChatWorker and SupportAgent Genome templates include collaboration capabilities |
| Bible/04-Execution/Security/IDS/000-Overview.md | IDS â€” Participant identity verification for session access |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” Core principles for collaborative interaction |
