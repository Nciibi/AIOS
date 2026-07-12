# AIOS Bible â€” Brain
## 000 â€” Conversation OS

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Conversation |
| Document ID | AIOS-BBL-002-CON-000 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Conversation OS manages Sou's dialogue with users. It handles multi-turn conversation context, turn management, user intent routing, modality adaptation, and response delivery. While the Context System manages the global context window (everything Sou is aware of), Conversation OS manages the interactive flow â€” the back-and-forth between Sou and the user.

Conversation OS is the interface between Sou and the user. It packages Sou's internal reasoning into user-facing messages and delivers user input to Sou.

## Architecture

```
User (via any modality: text, voice, API)
   â–²
   â”‚
   â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           Conversation OS                   â”‚
â”‚                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚ Session   â”‚  â”‚ Turn     â”‚  â”‚ Modality  â”‚ â”‚
â”‚  â”‚ Manager   â”‚â”€â–ºâ”‚ Manager  â”‚â”€â–ºâ”‚ Adapter   â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜ â”‚
â”‚                                    â”‚       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚       â”‚
â”‚  â”‚ Intent   â”‚  â”‚ Response â”‚       â”‚       â”‚
â”‚  â”‚ Router   â”‚  â”‚ Builder  â”‚       â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”˜
                                     â”‚
                                     â–¼
                            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                            â”‚  Sou via ACF â”‚
                            â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Conversation OS is the entry point for user interactions into the Brain. All user input (regardless of modality) enters through Conversation OS, which prepares it for Sou's consumption. All user-facing responses exit through Conversation OS, which adapts them to the appropriate modality.

## Core Concepts

### Conversation Model

```
ConversationSession {
  session_id: string
  user_id: string
  modality: "text" | "voice" | "api" | "multimodal"
  status: "active" | "idle" | "paused" | "ended"
  started_at: timestamp
  last_activity: timestamp
  turn_count: number
  metadata: {
    user_preferences: UserPreferences
    active_channels: string[]
    context_tags: string[]
  }
}

ConversationTurn {
  turn_id: string
  session_id: string
  turn_number: number
  role: "user" | "sou" | "system"
  content: TurnContent
  modality: string
  timestamp: timestamp
  response_to?: string         // turn_id this is responding to
  metadata: {
    processing_time_ms: number
    intent?: string
    sentiment?: number         // -1.0 (negative) â€“ 1.0 (positive)
    confidence?: number        // 0.0â€“1.0
  }
}

TurnContent {
  text: string
  attachments?: Attachment[]
  structured_data?: Record<string, unknown>
}

UserPreferences {
  formality: number            // 0.0â€“1.0
  verbosity: number            // 0.0â€“1.0
  preferred_modality: string
  timezone: string
  language: string
  accessibility: string[]      // e.g., "screen_reader", "high_contrast"
}
```

### 1. Session Manager

Manages the lifecycle of conversation sessions:

| Session State | Description | Enter | Exit |
|---------------|-------------|-------|------|
| active | Ready for interaction | User initiates | Session ends |
| idle | No activity, waiting timeout | No input for N seconds | Input arrives or timeout |
| paused | Suspended by user or system | User/system pauses | User/system resumes |
| ended | Session terminated | User ends or timeout | Session archived |

Session timeout:
- Idle timeout: 5 minutes of inactivity â†’ auto-pause
- Absolute timeout: 24 hours â†’ force-end
- Max idle sessions: 10 per user â†’ oldest auto-ended

Session state is persisted in Memory OS. Active sessions are cached in Conversation OS.

### 2. Turn Manager

Manages the turn-by-turn flow of conversation:

| Turn Phase | Responsibility | Duration |
|------------|----------------|----------|
| Receive | Accept user input via modality adapter | < 100ms |
| Parse | Extract intent, entities, sentiment | < 500ms |
| Route | Forward to Sou via ACF | < 100ms |
| Process | Sou processes and produces response | Variable |
| Build | Package response for modality | < 200ms |
| Deliver | Send response to user | < 100ms |

Turn management includes:
- Turn ordering: Ensures turns are processed in sequence
- Turn deduplication: Prevents duplicate processing of the same input
- Turn timeout: If Sou doesn't respond within 30 seconds, timeout and notify user
- Turn history: Maintains a sliding window of recent turns for context

### 3. Modality Adapter

Adapts input and output for different communication modalities:

| Modality | Input Adaptation | Output Adaptation |
|----------|-----------------|-------------------|
| Text | Direct passthrough | Format with markdown, code blocks |
| Voice | Speech-to-text via Voice System | Text-to-speech via Voice System |
| API | Parse structured request | Return structured response |
| Multimodal | Combine text + image/audio | Deliver text + optional media |

The Modality Adapter allows Sou to be modality-agnostic. Sou always processes text internally; the adapter handles translation to/from the user's modality.

### 4. Intent Router

Routes user input based on detected intent before it reaches Sou:

| Intent | Example | Route | Sou Receives |
|--------|---------|-------|--------------|
| question | "What is X?" | Direct to Sou | Full query |
| command | "Do X" | Direct to Sou | Full command |
| chit-chat | "How are you?" | Direct to Sou (with personality context) | Greeting + personality |
| meta | "What can you do?" | Direct to Sou (capability context) | Capability inquiry |
| feedback | "That was wrong" | Direct to Sou (with reflection context) | Feedback + reflection trigger |
| system | "Change settings" | Route to Personality/Settings | Setting change request |
| emergency | "Stop everything" | Interrupt via Attention System | Immediate interrupt |

The Intent Router is lightweight â€” it classifies intent using a simple rule-based matcher before passing to Sou. Complex intent resolution is handled by Sou via Cognitive OS.

### 5. Response Builder

After Sou produces a response, the Response Builder packages it for delivery:

| Component | Behavior |
|-----------|----------|
| Style application | Apply personality style profile |
| Formatting | Add markdown, code blocks, lists |
| Attachment handling | Process file references, images |
| Modality conversion | Text â†’ speech if voice modality |
| Length adjustment | Truncate or summarize if exceeds limits |
| Continuation | Split long responses into chunks |
| Confidence annotation | Add confidence indicators for uncertain answers |

## Interfaces

### Conversation OS API (via ACF)

#### User-Facing (from external channels)

| Method | Auth | Description |
|--------|------|-------------|
| `receiveMessage(session_id, content, modality)` | User token | Receive user input |
| `sendMessage(session_id, content, modality)` | Sou | Deliver response to user |
| `createSession(user_id, modality, preferences?)` | User token | Start a conversation session |
| `endSession(session_id)` | User or Sou | End a conversation session |
| `getSession(session_id)` | User or Sou | Get session state |
| `pauseSession(session_id)` | User or Sou | Pause conversation |

#### Brain-Facing (internal to Brain)

| Method | Auth | Description |
|--------|------|-------------|
| `deliverInput(session_id, turn)` | Conversation OS â†’ Sou | Deliver parsed user input to Sou |
| `receiveResponse(session_id, response)` | Sou â†’ Conversation OS | Receive Sou's response for delivery |
| `getTurnHistory(session_id, limit?)` | Sou only | Get recent turn history |
| `injectSystemMessage(session_id, content)` | Sou only | Inject system message into conversation |
| `updatePreferences(session_id, updates)` | Sou only | Update user preferences |

### Internal Interfaces

```
interface ModalityCodec {
  modality: string
  encode(content: TurnContent): EncodedOutput
  decode(input: EncodedInput): TurnContent
}

interface IntentClassifier {
  classify(input: TurnContent, context: ConversationSession): Intent
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `CONV.SessionCreated` | session_id, user_id, modality | Conversation session started |
| `CONV.SessionEnded` | session_id, turn_count, duration | Session ended |
| `CONV.SessionPaused` | session_id, reason | Session paused |
| `CONV.UserInputReceived` | turn_id, session_id, modality | User input accepted |
| `CONV.UserInputDelivered` | turn_id, session_id, latency_ms | Input delivered to Sou |
| `CONV.ResponseBuilt` | turn_id, session_id, response_length | Response packaged |
| `CONV.ResponseDelivered` | turn_id, session_id, modality, latency_ms | Response sent to user |
| `CONV.TurnTimeout` | turn_id, session_id | Sou took too long to respond |
| `CONV.IntentDetected` | turn_id, intent, confidence | Intent classified |
| `CONV.ModalityAdapted` | from_modality, to_modality, turn_id | Modality conversion occurred |
| `CONV.SouInterrupted` | turn_id, reason | Sou interrupted during processing |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CONV-001 | Every user message has exactly one response | Algorithmic â€” turn pairing enforced |
| CONV-002 | Turn ordering is strictly sequential | Architectural â€” Turn Manager sequences turns |
| CONV-003 | Sou processes text internally regardless of modality | Architectural â€” Modality Adapter normalizes input |
| CONV-004 | Conversation OS is stateless â€” sessions live in Memory OS | Architectural â€” no internal persistence |
| CONV-005 | User preferences are persistent across sessions | API-level â€” preferences stored in Memory OS |
| CONV-006 | Sessions auto-end after 24 hours | Algorithmic â€” Session Manager enforces timeout |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Conversation OS is a Brain Service |
| Brain/Sou/000-Overview.md | Sou receives user input and produces responses via Conversation OS |
| Brain/Personality/000-Overview.md | Personality style is applied to responses |
| Brain/Attention/000-Overview.md | User input generates attention signals |
| Brain/Context/000-Overview.md | Conversation turns are pushed to the context window |
| Brain/Memory/ | Session state and preferences persisted here |
| Brain/Voice/ | Voice modality uses Voice System for STT/TTS |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown session_id | `CONV_SESSION_NOT_FOUND` | Create new session or return error |
| Sou unresponsive (timeout) | `CONV_SOU_TIMEOUT` | Send "taking longer than expected" to user |
| Modality not supported | `CONV_UNSUPPORTED_MODALITY` | Return error; list supported modalities |
| Turn processing race condition | `CONV_TURN_RACE` | Queue conflicting turn; process in order |
| Session limit exceeded | `CONV_SESSION_LIMIT` | Auto-end oldest idle session |
| Message too long | `CONV_MESSAGE_TOO_LONG` | Truncate and notify user |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Conversation OS does one thing: manage dialogue flow |
| R2 â€” Dependency Order | Depends on Memory OS, Attention System; no upward deps |
| R3 â€” DRY | Session model defined once in Conversation Model |
| R4 â€” Builder Pattern | Response built by Intent Router â†’ Sou â†’ Response Builder |
| R5 â€” Liskov Substitution | Any ModalityCodec implements the interface |
| R6 â€” DI over Singletons | Modality codecs and intent classifiers injected |
| R9 â€” Deterministic | Same input produces same response (Sou may vary) |
| R10 â€” Simpler Over Complex | Turn management uses sequential ordering |
| R13 â€” Design for Failure | Turn timeouts always produce user notification |
| R14 â€” Paved Path | All user input flows through `receiveMessage` |
| R15 â€” Open/Closed | New modalities added via ModalityCodec, not by modifying core |
