# AIOS Bible â€” Interfaces
## UI â€” 000: Human Interface

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-UI-000 |
| Source Laws | Law 1 â€” Law of Origin, Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Human Interface is the general-purpose interaction layer between humans and AIOS. Where the Governance Console is for governance-critical actions, the Human Interface is for everything else: conversing with Sou, issuing commands, receiving notifications, approving routine requests, and visualizing system state. It is the primary surface through which humans experience AIOS.

Every human interaction through this interface is a first-class communication that flows through ACF (Law 3) and produces evidence (Law 4). The Human Interface is not a side channel â€” it is a constitutional communication path with the same observability guarantees as any inter-entity message.

## Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                  Human Interface                        â”‚
â”‚                                                         â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚ Conversationalâ”‚ â”‚  Command   â”‚  â”‚   Notification    â”‚  â”‚
â”‚  â”‚   Channel   â”‚  â”‚  Channel   â”‚  â”‚   Channel        â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚
â”‚        â”‚                â”‚                 â”‚            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚  Approval   â”‚  â”‚  Request   â”‚  â”‚   Visualization   â”‚  â”‚
â”‚  â”‚   Channel   â”‚  â”‚  Formatter â”‚  â”‚   Channel        â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚
â”‚        â”‚                â”‚                 â”‚            â”‚
â”‚        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜            â”‚
â”‚                         â”‚                              â”‚
â”‚                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”                     â”‚
â”‚                â”‚  Interface Hub   â”‚                     â”‚
â”‚                â”‚  (ACF-backed)    â”‚                     â”‚
â”‚                â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜                     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                          â”‚
                          â–¼
        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
        â”‚ Brain (Sou, Conversation OS), ACF,       â”‚
        â”‚ Notification System, Dashboard           â”‚
        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Core Concepts

### 1. Conversational Channel

The primary mode of human-AIOS interaction: natural language dialogue with Sou via the Conversation OS. Humans ask questions, give instructions, and receive explanations. The conversational channel maintains session context, supports multi-turn dialogue, and routes complex intents to the appropriate Brain service.

### 2. Command Channel

A structured, typed interface for precise operations: "create mission X", "pause workflow Y", "show budget Z". Commands are validated, authorized, and executed through the standard verification pipeline. Commands are the deterministic alternative to natural language for routine operations.

### 3. Notification Channel

AIOS-initiated messages to humans: "Mission X completed", "Agent Y requests promotion", "Budget Z at 90%". Notifications are prioritized, actionable (may include inline approve/deny), and deduplicated. They never bypass the evidence chain â€” each notification references its source event.

### 4. Approval Channel

Human-in-the-loop confirmation for routine decisions that require human sign-off but are not governance-critical: approving a workflow gate, confirming a resource allocation, acknowledging a risk. Distinct from the Governance Console's override/certification â€” these are operational approvals, not constitutional ones.

### 5. Visualization Channel

Renders system state for human consumption: agent status, mission progress, resource usage, security posture. Visualization pulls from the Dashboard and AOP but formats for human reading. Interactive elements (drill-down, filter) are read-only unless they trigger a command.

### 6. Request Formatter

Translates between human intent and Brain/ACF message formats. Parses natural language or structured commands into typed requests, and renders Brain responses into human-readable form. Maintains schema validation against the Interoperability Protocol contracts.

## Data Model

```typescript
interface HumanSession {
  sessionId: string;
  humanId: string;
  channel: 'conversational' | 'command' | 'notification' | 'approval' | 'visualization';
  contextId: string;  // conversation or workflow context
  startedAt: Timestamp;
  idleTimeoutSeconds: number;
  evidenceRef: string;
}

interface HumanMessage {
  messageId: string;
  sessionId: string;
  humanId: string;
  content: string;  // natural language or structured command
  intent: ParsedIntent;
  timestamp: Timestamp;
  evidenceRef: string;
}

interface Notification {
  notificationId: string;
  humanId: string;
  priority: 'low' | 'normal' | 'high' | 'critical';
  title: string;
  body: string;
  actions?: NotificationAction[];  // inline approve/deny
  sourceEventRef: string;  // evidence reference of triggering event
  deliveredAt: Timestamp;
}

interface ApprovalRequest {
  requestId: string;
  humanId: string;
  subject: string;  // what needs approval
  context: Record<string, unknown>;
  timeoutSeconds: number;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  evidenceRef: string;
}

interface ParsedIntent {
  action: string;
  target: string;
  parameters: Record<string, unknown>;
  confidence: number;
  needsConfirmation: boolean;
}
```

## Interfaces

### Human Interface API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `sendMessage(sessionId, content)` | Verified Human | Send a conversational or command message |
| `executeCommand(sessionId, command)` | Verified Human | Run a structured command |
| `listNotifications(humanId)` | Verified Human | Retrieve pending notifications |
| `acknowledgeNotification(notificationId)` | Verified Human | Mark notification read |
| `respondToNotification(notificationId, action)` | Verified Human | Take inline action on notification |
| `respondToApproval(requestId, decision)` | Verified Human | Approve/deny an approval request |
| `getVisualization(contextId, view)` | Verified Human | Retrieve a formatted system view |
| `startSession(humanId, channel)` | Verified Human | Begin a human interaction session |

### Internal Interfaces

```typescript
interface InterfaceHub {
  route(message: HumanMessage): Promise<RoutedIntent>;
  format(response: BrainResponse): Promise<HumanReadable>;
  sessionFor(humanId: string, channel: string): Promise<HumanSession>;
}

interface IntentParser {
  parse(content: string): Promise<ParsedIntent>;
  validate(intent: ParsedIntent): ValidationResult;
  needsConfirmation(intent: ParsedIntent): boolean;
}

interface NotificationDispatcher {
  dispatch(notification: Notification): Promise<void>;
  dedupe(key: string): boolean;
  escalate(notification: Notification): Promise<void>;
}

interface ApprovalBroker {
  request(req: ApprovalRequest): Promise<void>;
  resolve(requestId: string, decision: 'approved' | 'denied'): Promise<void>;
  timeout(requestId: string): Promise<void>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Interface Hub | Routes human messages to Brain services; formats responses |
| Intent Parser | Parses natural language / commands into typed intents |
| Notification Dispatcher | Delivers and deduplicates AIOS-initiated messages |
| Approval Broker | Manages routine human approval requests |
| Session Manager | Lifecycle of human interaction sessions |
| Visualization Renderer | Formats system state views for humans |

## Data Flow

```
Human sends message via channel
        â”‚
        â–¼
Interface Hub receives via ACF
        â”‚
        â–¼
Intent Parser parses and validates
        â”‚
        â”œâ”€â”€ Conversational â”€â”€â–º Conversation OS â”€â”€â–º Sou responds
        â”‚
        â”œâ”€â”€ Command â”€â”€â–º Verification Pipeline â”€â”€â–º Execution
        â”‚
        â””â”€â”€ Approval/Notification â”€â”€â–º Broker/Dispatcher
        â”‚
        â–¼
Response formatted by Interface Hub
        â”‚
        â–¼
Delivered to human; evidence recorded (Law 4)
```

## Events

| UI.EventType | Produced When | Fields |
|-------|--------|-------------|
| `UI.SessionStarted` | sessionId, humanId, channel | Human interaction session opened |
| `UI.MessageReceived` | messageId, sessionId, intent | Human message parsed |
| `UI.CommandExecuted` | sessionId, command, result | Structured command run |
| `UI.NotificationSent` | notificationId, humanId, priority | Notification delivered |
| `UI.NotificationAcked` | notificationId, humanId | Notification acknowledged |
| `UI.ApprovalRequested` | requestId, humanId, subject | Routine approval requested |
| `UI.ApprovalResolved` | requestId, decision, humanId | Approval decision recorded |
| `UI.SessionEnded` | sessionId, humanId | Session closed |
| `UI.IntentUnclear` | sessionId, content, confidence | Parser low-confidence; clarification requested |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Human not authenticated | `UI_AUTH_REQUIRED` | Block; require authentication |
| Intent parse failed | `UI_PARSE_FAILED` | Request clarification from human |
| Intent confidence below threshold | `UI_LOW_CONFIDENCE` | Request human confirmation before acting |
| Command not authorized | `UI_COMMAND_DENIED` | Reject; human lacks permission |
| Approval request expired | `UI_APPROVAL_EXPIRED` | Mark expired; notify requester |
| Notification delivery failed | `UI_NOTIFY_FAILED` | Retry with backoff; escalate if persists |
| Session idle timeout | `UI_SESSION_EXPIRED` | Close session; require re-auth to resume |
| Duplicate notification | `UI_NOTIFY_DUPLICATE` | Suppress; update existing notification |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| UI-001 | Every human message flows through ACF (Law 3) | Architectural â€” Interface Hub uses ACF transport |
| UI-002 | Every human interaction produces evidence (Law 4) | Architectural â€” messages logged to EVS |
| UI-003 | Humans are authenticated before any action | Constitutional â€” no anonymous interaction |
| UI-004 | Commands are validated before execution | Algorithmic â€” Intent Parser validates against schemas |
| UI-005 | Approval requests are idempotent | Architectural â€” decision state is terminal |
| UI-006 | Notifications reference their source event | Algorithmic â€” sourceEventRef required on dispatch |
| UI-007 | Sessions expire after idle timeout | Algorithmic â€” Session Manager enforces timeout |


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
| R1 â€” Modulsingularity | UI owns human interaction exclusively; Brain owns responses; ACF owns transport |
| R2 â€” Dependency Order | Depends on Conversation OS, ACF, Notification System, Dashboard; no cycles |
| R3 â€” DRY | Message schemas defined via IOP contracts; UI renders, does not redefine |
| R4 â€” Builder Pattern | Approval requests and notifications use builder for validation |
| R9 â€” Deterministic | Same command + same state = same result; conversations are logged for replay |
| R10 â€” Simpler Over Complex | Conversational + command channels cover most needs; advanced views opt-in |
| R13 â€” Design for Failure | Parse failure requests clarification; auth failure preserves session context |
| R14 â€” Paved Path | Conversational chat is the default human entry point |
| R15 â€” Open/Closed | New channels register via Interface Hub extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Brain/Conversation/000-Overview.md | Conversation OS powers the conversational channel |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou is the strategic authority humans converse with |
| Bible/06-Services/ACF/000-Overview.md | ACF is the transport for all human messages |
| Bible/06-Services/Interop/000-Overview.md | IOP contracts define message schemas UI validates against |
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console â€” governance-critical human actions |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard â€” visualization backend for the visualization channel |
| Bible/05-Platform/004-EVS.md | EVS stores human interaction evidence |
| Bible/05-Platform/Observability/000-AOP.md | AOP monitors human interaction health |
| Physics/009-Interaction.md | Interaction invariants â€” human is an interaction participant |
| Physics/005-Events.md | Evidence invariants â€” every interaction is logged |
