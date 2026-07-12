# AIOS Bible â€” Brain
## 001 â€” Dialogue State

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Conversation |
| Document ID | AIOS-BBL-002-CON-001 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/004-Sessions.md, Physics/006-Lifecycles.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Dialogue State tracks the current state of a conversation â€” active topic, user intent, conversational context beyond turn history, pending questions, clarification state, and conversation flow phase. It is the session-level representation of "where are we in this conversation?" While Turn History records what was said, Dialogue State records what it means â€” the semantic and pragmatic progress of the interaction. Dialogue State is session-scoped: created on session init, mutated on every turn, and archived on session end.

Under CONV-003 and CONV-004, Dialogue State is the authoritative source for conversational context. No intent, topic, or phase information lives outside this component.

## Data Model

### DialogueState

```typescript
DialogueState {
  session_id: string
  current_topic: Topic | null
  topic_history: Topic[]                // Ordered list of topics discussed
  active_intent: IntentState | null
  pending_clarifications: ClarificationState[]
  conversation_phase: ConversationPhase
  flow_state: FlowState
  user_intent_stack: IntentState[]      // LIFO â€” nested/overlapping intents
  metadata: {
    turn_count: number
    state_version: number               // Monotonic version for optimistic concurrency
    last_updated: timestamp
    sou_confidence: number              // 0.0â€“1.0, Sou's confidence in current understanding
    active_duration_ms: number
    tags: string[]
  }
}
```

### Topic

```typescript
Topic {
  topic_id: string
  label: string                         // Human-readable name, e.g. "Project Requirements"
  parent_topic: string | null           // topic_id of parent, null if root
  subtopics: string[]                   // topic_ids of children
  started_at: timestamp
  last_active: timestamp
  is_active: boolean
  turn_count: number                    // Turns spent on this topic
  depth: number                         // 0 for root, 1 for child, etc.
  confidence: number                    // 0.0â€“1.0, how sure we are this is the topic
}
```

### IntentState

```typescript
IntentState {
  intent_id: string
  intent_type: string                   // e.g. "create_task", "ask_question", "update_setting"
  parameters: Record<string, ParameterState>
  confidence: number                    // 0.0â€“1.0
  status: "pending" | "active" | "resolved" | "abandoned"
  detected_at: timestamp
  last_updated: timestamp
  source_turn_id: string                // Turn that triggered this intent
  parent_intent_id: string | null       // For nested intents
}

ParameterState {
  value: unknown                        // Resolved value, null if unresolved
  resolved: boolean
  required: boolean
  resolved_at: timestamp | null
  resolution_turn_id: string | null     // Turn that resolved this parameter
  source: string                        // How it was resolved: "user_input" | "inferred" | "default"
}
```

### ClarificationState

```typescript
ClarificationState {
  clarification_id: string
  question: string                      // The clarification question asked to user
  asked_at: timestamp
  resolved: boolean
  resolution: string | null             // User's response, null if unresolved
  resolution_turn_id: string | null
  context: {
    intent_id: string | null            // Intent this clarification belongs to
    topic_id: string | null             // Topic this clarification belongs to
    parameter: string | null            // Parameter being clarified
    phase: ConversationPhase            // Phase when clarification was asked
  }
  retry_count: number                   // How many times clarification was re-asked
}
```

### ConversationPhase

```typescript
ConversationPhase =
  | "greeting"              // Opening the conversation
  | "information_gathering" // Collecting data from user
  | "task_execution"        // Sou is performing a task
  | "clarification"         // Resolving ambiguity
  | "confirmation"          // Confirming actions with user
  | "response"              // Delivering final response
  | "closing"               // Ending the conversation
```

### FlowState

```typescript
FlowState {
  current_phase: ConversationPhase
  phase_history: {
    phase: ConversationPhase
    entered_at: timestamp
    duration_ms: number
  }[]
  expected_next_input_type: string      // e.g. "confirmation", "parameter_value", "topic_selection"
  flow_constraints: {
    requires_confirmation: boolean
    requires_clarification: boolean
    required_parameters: string[]       // Parameters needed before phase can advance
    completion_condition: string        // Condition to exit current phase
    timeout_ms: number | null           // Max time in current phase
  }
}
```

## Slots

Dialogue State is organized into logical slots that map to distinct aspects of conversational context:

| Slot | Cardinality | Eviction | Contents |
|------|-------------|----------|----------|
| `current_topic` | 1 | None | The single active topic Sou is discussing with the user |
| `topic_history` | 50 | FIFO | Ordered log of topics visited this session |
| `active_intent` | 1 | None | The primary intent Sou is currently resolving |
| `intent_stack` | 10 | FIFO | Nested/overlapping intents (LIFO access) |
| `pending_clarifications` | 10 | FIFO | Open questions awaiting user response |
| `phase_history` | 100 | FIFO | Chronological log of phase transitions |
| `flow_state` | 1 | None | Current phase, constraints, and expected input |

### Slot Behavior

```
Slot: intent_stack
  Access: pushIntent(intent) â†’ popIntent() â†’ peekIntent()
  Eviction: When full, lowest-confidence pending intent is abandoned
  Use case: User asks "Create a task" â†’ while gathering params, asks "What tasks exist?"
    Stack: [create_task_intent, query_tasks_intent]
    â†’ pop query_tasks (resolved) â†’ back to create_task

Slot: topic_history
  Access: recordTopic(topic) â†’ getTopicSequence() â†’ getTopicDepth(topic_id)
  Eviction: When full, oldest topic is pruned (summary retained in metadata)
  Use case: User shifts from "Project Setup" â†’ "Dependencies" â†’ "Testing"
    History: [Project Setup, Dependencies, Testing]

Slot: pending_clarifications
  Access: addClarification(q) â†’ resolveClarification(id, answer) â†’ getOpenQuestions()
  Eviction: When full, oldest unresolved clarification is auto-resolved as "user skipped"
  Use case: Sou asks "Which priority?" â†’ user talks about something else â†’ clarification times out
```

## Dialogue State Lifecycle

### Per-Session Lifecycle

```
Session Init
    â”‚
    â–¼
State Created
    â”‚
    â”œâ”€â”€ Create DialogueState with session_id
    â”œâ”€â”€ Set conversation_phase = "greeting"
    â”œâ”€â”€ Initialize empty topic_history, intent_stack, pending_clarifications
    â”œâ”€â”€ Set flow_state with default constraints
    â””â”€â”€ Emit CONV.DialogueStateUpdated
    â”‚
    â–¼
Active Session (per turn)
    â”‚
    â”œâ”€â”€ Topic Tracking
    â”‚   â”œâ”€â”€ Detect topic from user input
    â”‚   â”œâ”€â”€ Check for topic shift (threshold: N turns on new subject)
    â”‚   â”œâ”€â”€ Update topic depth if navigating subtopics
    â”‚   â”œâ”€â”€ Detect topic return (user revisits previous topic)
    â”‚   â””â”€â”€ Emit CONV.TopicShifted / CONV.TopicDepthChanged / CONV.TopicReturned
    â”‚
    â”œâ”€â”€ Intent Tracking
    â”‚   â”œâ”€â”€ Detect intent from user input
    â”‚   â”œâ”€â”€ Push to intent_stack if nested
    â”‚   â”œâ”€â”€ Update parameter resolution status
    â”‚   â”œâ”€â”€ Resolve intent if all required parameters gathered
    â”‚   â”œâ”€â”€ Abandon intent if user changes subject
    â”‚   â””â”€â”€ Emit CONV.IntentDetected / CONV.IntentResolved / CONV.IntentAbandoned
    â”‚
    â”œâ”€â”€ Phase Transitions
    â”‚   â”œâ”€â”€ Evaluate phase transition conditions
    â”‚   â”œâ”€â”€ Transition to new phase if conditions met
    â”‚   â”œâ”€â”€ Update flow_state constraints for new phase
    â”‚   â””â”€â”€ Emit CONV.PhaseTransitioned
    â”‚
    â””â”€â”€ Clarification Management
        â”œâ”€â”€ If ambiguity detected, create ClarificationState
        â”œâ”€â”€ Add to pending_clarifications
        â”œâ”€â”€ Emit CONV.ClarificationAsked
        â”œâ”€â”€ On user response, resolve clarification
        â”œâ”€â”€ Update related intent parameter if applicable
        â””â”€â”€ Emit CONV.ClarificationResolved
    â”‚
    â–¼
Session End
    â”‚
    â”œâ”€â”€ Emit CONV.DialogueArchived
    â”œâ”€â”€ Write final DialogueState to Episodic Memory for post-session analysis
    â””â”€â”€ Destroy in-memory state
```

### Phase State Machine

```
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚                                     â”‚
                    â–¼                                     â”‚
              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”‚
  Start â”€â”€â–º   â”‚ greeting â”‚â”€â”€â”€â”€â”€â”€â–º information_gathering â”‚â”€â”€â”˜
              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                         â”‚
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â–¼                    â–¼                    â–¼
              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
              â”‚clarificationâ”‚â—„â”€â”€â”€â”€â”€â”€â”€â”‚task_executionâ”‚â”€â”€â”€â”€â”€â”€â–ºâ”‚confirmationâ”‚
              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜        â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜       â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜
                    â–²                    â”‚                    â”‚
                    â”‚                    â–¼                    â”‚
                    â”‚              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”              â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚ response â”‚â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                   â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜
                                        â”‚
                                        â–¼
                                   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                                   â”‚  closing  â”‚ â”€â”€â–º End
                                   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

#### Phase Transition Rules

| From | To | Condition |
|------|----|-----------|
| greeting | information_gathering | Initial greeting exchanged |
| greeting | task_execution | User immediately issues command |
| information_gathering | task_execution | All required parameters collected |
| information_gathering | clarification | Ambiguous or missing parameter detected |
| task_execution | clarification | Sou needs additional information |
| task_execution | confirmation | Action requires user approval |
| task_execution | response | Task complete, ready to deliver |
| clarification | information_gathering | Clarification resolved, more params needed |
| clarification | task_execution | Clarification resolved, can proceed |
| clarification | response | Clarification was the final step |
| confirmation | task_execution | User confirmed, execute action |
| confirmation | clarification | User uncertainty detected during confirmation |
| confirmation | information_gathering | User rejected, needs to provide new info |
| response | closing | Response delivered, no follow-up |
| response | information_gathering | User asks follow-up question |
| closing | (end) | Goodbye exchanged or timeout |

## Topic Management

### Topic Detection

Topic is extracted from each user turn using lightweight classification. The topic space is open-ended â€” topics are derived from user input content, not from a predefined list.

```
detectTopic(turn_content, context):
  1. Extract key noun phrases from user input
  2. Compare against current_topic label
  3. If similarity > 0.7: same topic (increment topic turn_count)
  4. If similarity < 0.3: potential new topic
  5. If 0.3 <= similarity <= 0.7: subtopic of current topic
```

### Topic Shift Detection

A topic shift is declared when the user spends N consecutive turns on a different subject:

| Threshold | Value | Behavior |
|-----------|-------|----------|
| `shift_turns` | 2 | Consecutive turns on new subject â†’ shift |
| `shift_confidence` | 0.6 | Topic confidence must exceed threshold |
| `shift_cooldown` | 3 | Min turns before another shift can be declared |

```
Topic Shift Detection:
  new_topic_confidence = classify(user_input)
  If new_topic_confidence >= 0.6 AND new_topic != current_topic:
    consecutive_new_topic_turns++
    If consecutive_new_topic_turns >= 2:
      topic_shifted(current_topic, new_topic)
      current_topic = new_topic
      consecutive_new_topic_turns = 0
  Else:
    consecutive_new_topic_turns = 0
```

### Topic Depth Tracking

Topics form a tree. Depth is calculated as distance from the root topic:

```
Root Topic (depth 0): "Project Planning"
  â””â”€ Subtopic (depth 1): "Architecture"
      â””â”€ Subtopic (depth 2): "Database Schema"
          â””â”€ Subtopic (depth 3): "Table Design"
```

Depth is bounded at 5 levels. Going deeper than 5 flattens to depth 5 with a parent reference to depth 4.

### Topic Return Detection

A topic return occurs when the user revisits a previously discussed topic after at least 2 intervening topic shifts:

```
Topic Return:
  If new_topic matches any topic in topic_history (by topic_id):
    AND topic already visited and not current_topic:
    AND topic.last_active was at least 2 shifts ago:
    â†’ Emit CONV.TopicReturned
    â†’ Restore subtopic context from history
    â†’ Set current_topic to the matched topic (not a new instance)
```

### Topic Hierarchy

```
Topic Hierarchy within a session:
  session_topics: Map<topic_id, Topic>
  adjacency_list: Map<topic_id, topic_id[]>  // parent â†’ children
  root_topics: topic_id[]                    // Topics with parent_topic = null

  getTopicPath(topic_id): Topic[]            // Root â†’ ... â†’ topic
  getSubtopicTree(topic_id): TreeNode        // Full subtree
  getSiblingTopics(topic_id): Topic[]        // Same parent
```

## Intent Tracking

### Intent Stack (LIFO)

Intents can be nested. When the user interrupts a primary intent with a secondary intent, the secondary is pushed onto the stack:

```
Intent Stack Operations:
  pushIntent(intent):
    Set intent.parent_intent_id = peekIntent()?.intent_id
    Push onto user_intent_stack
    Set active_intent = intent
    Emit CONV.IntentDetected

  popIntent():
    prev_intent = user_intent_stack.pop()
    Set active_intent = peekIntent()
    Return prev_intent

  peekIntent():
    Return user_intent_stack[user_intent_stack.length - 1] || null
```

### Parameter Resolution Tracking

Each intent carries a map of parameters. Parameters are tracked as resolved or unresolved:

```
Parameter Resolution:
  resolveParameter(intent_id, param_name, value, source):
    param = active_intent.parameters[param_name]
    param.value = value
    param.resolved = true
    param.resolved_at = now()
    param.resolution_turn_id = current_turn_id
    param.source = source

  getMissingParameters(intent_id): string[]
    Return active_intent.parameters
      .filter(p => p.required && !p.resolved)
      .map(p => param_name)

  isIntentReady(intent_id): boolean
    Return getMissingParameters(intent_id).length === 0
```

### Intent Resolution vs Abandonment

| Status | Condition | Next Action |
|--------|-----------|-------------|
| pending | Just detected, no parameters resolved | Awaiting user input |
| active | At least one parameter resolved | Continue gathering |
| resolved | All required parameters gathered, intent completed | Pop from stack, transition phase |
| abandoned | User changed subject or explicitly canceled | Emit CONV.IntentAbandoned, pop from stack |

### Pending Intent Carry-Over

If a session ends with unresolved intents, those intents are serialized to Episodic Memory for potential future session continuation:

```
Pending Intent Carry-Over:
  On session end:
    If active_intent exists and status !== "resolved":
      Serialize intent state to Episodic Memory
      Tag with session_id and intent_id
      On next session with same user:
        Check for carry-over intents
        If found, prompt user: "Would you like to continue with [intent]?"
        If yes, restore intent state and resume
```

## Clarification Management

### Open Questions List

Pending clarifications are maintained as a prioritized list:

```
Pending Clarifications:
  Ordered by: asked_at (ascending â€” FIFO)
  Priority: clarification with associated active_intent > clarification without
  Display: Only the top 5 are surfaced to Sou
```

### Pending Clarifications per Topic/Intent

Clarifications are scoped to topics and intents:

```
Scope-based Clarification:
  Topic-scoped: "Which part of the architecture do you mean?"
    â†’ context.topic_id = current_topic.topic_id
  Intent-scoped: "What priority should this task have?"
    â†’ context.intent_id = active_intent.intent_id
    â†’ context.parameter = "priority"
```

### Clarification Resolution Flow

```
Clarification Resolution:
  1. Ambiguity detected during user input processing
  2. Create ClarificationState with question and context
  3. Add to pending_clarifications
  4. Emit CONV.ClarificationAsked
  5. FlowState sets expected_next_input_type = "clarification_response"
  6. Wait for user response:
     a. User provides clarifying information
        â†’ Resolve clarification
        â†’ Update related intent parameter if applicable
        â†’ Emit CONV.ClarificationResolved
        â†’ Transition back to previous phase
     b. User changes topic
        â†’ Clarification remains pending (retry_count + 1)
        â†’ If retry_count > 3, auto-resolve as "user abandoned"
     c. Timeout (30 seconds)
        â†’ Auto-resolve as "timeout"
        â†’ Emit CONV.ClarificationResolved with resolution = "timeout"
```

## CRUD Operations

### Store

```typescript
updateState(state: DialogueState): DialogueState
```

- Validates all invariants before persisting
- Increments `state_version`
- Sets `last_updated` to current timestamp
- Returns the updated state

### Read

```typescript
getState(session_id: string): DialogueState | null
getCurrentTopic(session_id: string): Topic | null
getActiveIntent(session_id: string): IntentState | null
getPendingClarifications(session_id: string): ClarificationState[]
getConversationPhase(session_id: string): ConversationPhase
getTopicHistory(session_id: string): Topic[]
getIntentStack(session_id: string): IntentState[]
```

- `getState` â€” full state snapshot
- `getCurrentTopic` â€” convenience accessor for active topic
- `getActiveIntent` â€” convenience accessor for active intent
- `getPendingClarifications` â€” unresolved clarifications only
- `getConversationPhase` â€” current phase string
- `getTopicHistory` â€” full ordered topic history
- `getIntentStack` â€” current intent stack (LIFO order)

### Update

```typescript
updateTopic(session_id: string, topic_update: Partial<Topic>): void
setIntent(session_id: string, intent: IntentState): void
updateIntentParams(session_id: string, intent_id: string, params: Record<string, unknown>): void
resolveIntent(session_id: string, intent_id: string): void
abandonIntent(session_id: string, intent_id: string): void
addClarification(session_id: string, question: string, context?: ClarificationContext): void
resolveClarification(session_id: string, clarification_id: string, response: string): void
transitionPhase(session_id: string, new_phase: ConversationPhase): void
pushIntent(session_id: string, intent: IntentState): void
popIntent(session_id: string): IntentState | null
```

- `updateTopic` â€” updates current topic or initiates topic shift
- `setIntent` â€” sets active intent (replaces current)
- `updateIntentParams` â€” resolves specific parameters by name
- `resolveIntent` â€” marks intent as resolved, pops from stack
- `abandonIntent` â€” marks intent as abandoned, pops from stack
- `addClarification` â€” creates and appends a ClarificationState
- `resolveClarification` â€” marks clarification resolved with user response
- `transitionPhase` â€” validates and executes phase transition
- `pushIntent` â€” pushes onto intent stack (nested intent)
- `popIntent` â€” pops from intent stack

### Delete

```typescript
removeClarification(session_id: string, clarification_id: string): void
archiveState(session_id: string): void
```

- `removeClarification` â€” removes a clarification (resolved or abandoned)
- `archiveState` â€” serializes final state to Episodic Memory, destroys in-memory state

## Internal Interfaces

```typescript
interface DialogueStateManager {
  // State lifecycle
  initializeState(session_id: string): DialogueState
  getState(session_id: string): DialogueState | null
  archiveState(session_id: string): void

  // Topic management
  updateTopic(session_id: string, topic_update: Partial<Topic>): void
  detectTopicShift(session_id: string, user_input: string): boolean
  getTopicDepth(session_id: string, topic_id: string): number
  detectTopicReturn(session_id: string, candidate_topic: Topic): boolean
  getTopicPath(session_id: string, topic_id: string): Topic[]

  // Intent tracking
  setIntent(session_id: string, intent: IntentState): void
  updateIntentParams(session_id: string, intent_id: string, params: Record<string, unknown>): void
  resolveIntent(session_id: string, intent_id: string): void
  abandonIntent(session_id: string, intent_id: string): void
  pushIntent(session_id: string, intent: IntentState): void
  popIntent(session_id: string): IntentState | null
  getMissingParameters(session_id: string, intent_id: string): string[]
  isIntentReady(session_id: string, intent_id: string): boolean

  // Clarification management
  addClarification(session_id: string, question: string, context?: ClarificationContext): void
  resolveClarification(session_id: string, clarification_id: string, response: string): void
  getPendingClarifications(session_id: string): ClarificationState[]
  getOpenQuestionsCount(session_id: string): number

  // Phase management
  transitionPhase(session_id: string, new_phase: ConversationPhase): void
  getConversationPhase(session_id: string): ConversationPhase
  canTransitionTo(session_id: string, target_phase: ConversationPhase): boolean
  setFlowConstraints(session_id: string, constraints: Partial<FlowConstraints>): void

  // Events
  on(callback: DialogueStateEventCallback): void
}

interface ClarificationContext {
  intent_id?: string
  topic_id?: string
  parameter?: string
}
```

## Usage Patterns

### Pattern 1: Multi-Turn Intent Resolution

```
1. User: "Create a task called 'Write docs'"
2. Dialogue State: IntentDetected { intent_type: "create_task", parameters: { title: "Write docs" } }
   â†’ Missing: priority, due_date, assignee
   â†’ Phase transitions: information_gathering â†’ clarification
   â†’ ClarificationAsked: "What priority should this task have?"
3. User: "High priority"
   â†’ resolveParameter("priority", "high")
   â†’ Missing: due_date, assignee
   â†’ ClarificationAsked: "When is this due?"
4. User: "Tomorrow"
   â†’ resolveParameter("due_date", "tomorrow")
   â†’ Missing: assignee
   â†’ ClarificationAsked: "Who should be assigned?"
5. User: "Me"
   â†’ resolveParameter("assignee", "me")
   â†’ All required parameters resolved â†’ IntentResolved
   â†’ Phase transitions: clarification â†’ task_execution
```

### Pattern 2: Topic Shift and Return

```
1. User discusses "Project Architecture" â†’ Topic: Architecture (depth 0)
2. User goes deeper: "Let's talk about the database layer"
   â†’ Subtopic: Database (depth 1, parent: Architecture)
3. User goes deeper: "Specifically the Postgres schema"
   â†’ Subtopic: Postgres Schema (depth 2, parent: Database)
4. User: "Anyway, getting back to the overall architecture..."
   â†’ TopicReturn detected: Architecture (depth 0)
   â†’ TopicDepthChanged: depth 2 â†’ depth 0
5. User: "And about the database..."
   â†’ TopicShift: Database (depth 1) â€” not a return, within topic tree
```

### Pattern 3: Nested Intent with Interruption

```
1. User: "Can you help me plan my week?"
   â†’ Intent: plan_week (pending)
2. User: "First, what meetings do I have tomorrow?"
   â†’ pushIntent: query_meetings (nested within plan_week)
   â†’ Stack: [plan_week, query_meetings]
3. Sou responds with meeting list
   â†’ resolveIntent: query_meetings
   â†’ popIntent â†’ back to plan_week
   â†’ Stack: [plan_week]
4. User: "Actually, never mind, I'll do it later"
   â†’ abandonIntent: plan_week
   â†’ Stack: []
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CONV.DialogueStateUpdated |     session_id, state_version, updated_fields | Dialogue State was modified |
| CONV.TopicShifted |     session_id, from_topic_id, to_topic_id, shift_type | User changed conversation topic |
| CONV.IntentDetected |     session_id, intent_id, intent_type, confidence | New intent detected from user input |
| CONV.IntentResolved |     session_id, intent_id, duration_ms, param_count | Intent completed successfully |
| CONV.IntentAbandoned |     session_id, intent_id, reason, turns_active | Intent abandoned by user |
| CONV.PhaseTransitioned |     session_id, from_phase, to_phase, reason | Conversation phase changed |
| CONV.ClarificationAsked |     session_id, clarification_id, question, context | Clarification question asked to user |
| CONV.ClarificationResolved |     session_id, clarification_id, resolution, method | Clarification answered (user/timeout/abandoned) |
| CONV.TopicDepthChanged |     session_id, topic_id, from_depth, to_depth | Topic depth level changed |
| CONV.TopicReturned |     session_id, topic_id, previous_active_timestamp | User returned to a previously discussed topic |
| CONV.DialogueArchived |     session_id, turn_count, phase, intent_count | Dialogue state archived on session end |
| CONV.IntentParamResolved |     session_id, intent_id, param_name, source | Individual intent parameter resolved |
| CONV.FlowConstraintActivated |     session_id, constraint, phase | Flow constraint became active |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DIAL-001 | Every Dialogue State is associated with exactly one session | Schema â€” `session_id` is required and unique |
| DIAL-002 | At most one active topic exists at any time | Algorithmic â€” `updateTopic` deactivates previous topic |
| DIAL-003 | At most one active intent exists at any time (intent stack top) | Algorithmic â€” push/pop enforces single active intent |
| DIAL-004 | Phase transitions follow the defined state machine (no illegal transitions) | Algorithmic â€” `transitionPhase` validates against transition table |
| DIAL-005 | Pending clarifications are resolved or removed before the associated intent is resolved | Algorithmic â€” `resolveIntent` checks for open clarifications; if any exist, intent cannot resolve |
| DIAL-006 | Dialogue State version is strictly monotonic | Algorithmic â€” `state_version` incremented on every write; concurrent write with stale version is rejected |
| DIAL-007 | Topic depth never exceeds 5 | Algorithmic â€” `updateTopic` flattens beyond depth 5 |
| DIAL-008 | Clarification retry count is bounded at 3 | Algorithmic â€” `addClarification` with retry_count >= 3 auto-resolves |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown session_id | `DIAL_SESSION_NOT_FOUND` | Return error; caller must initialize state first |
| Illegal phase transition | `DIAL_ILLEGAL_PHASE_TRANSITION` | Reject transition; log attempted transition for diagnostics |
| Stale state version (concurrent modification) | `DIAL_STALE_VERSION` | Return error; caller must re-read state and retry |
| Intent resolution with open clarifications | `DIAL_INTENT_HAS_OPEN_CLARIFICATIONS` | Return error; resolve or abandon clarifications first |
| Topic shift cooldown active | `DIAL_TOPIC_SHIFT_COOLDOWN` | Suppress shift; continue tracking as subtopic |
| Clarification retry limit exceeded | `DIAL_CLARIFICATION_RETRY_EXCEEDED` | Auto-resolve clarification as "user abandoned" |
| Intent stack overflow (>10 nested intents) | `DIAL_INTENT_STACK_OVERFLOW` | Abandon lowest-confidence pending intent |
| Topic depth exceeds maximum | `DIAL_TOPIC_DEPTH_EXCEEDED` | Flatten to max depth; log diagnostic |


## Cross-Cutting Concerns

### Security

Conversation OS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Conversation OS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Conversation OS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Conversation OS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Dialogue State handles only conversation-level semantic state, not turn history or session lifecycle |
| R2 â€” Dependency Order | Depends on Memory OS for persistence; depends on Conversation OS for turn events; no upward deps |
| R3 â€” DRY | Topic, Intent, Clarification models defined once in Data Model |
| R4 â€” Builder Pattern | State built by initializeState â†’ per-turn mutation â†’ archiveState |
| R5 â€” Liskov Substitution | Any DialogueStateManager implements the interface |
| R6 â€” DI over Singletons | Topic classifier, intent classifier, phase transition rules injected |
| R9 â€” Deterministic | Same sequence of inputs and state produces same state transitions |
| R10 â€” Simpler Over Complex | Uses stack-based intent model and explicit phase state machine |
| R13 â€” Design for Failure | Stale version detection prevents concurrent corruption; clarification timeout prevents deadlock |
| R14 â€” Paved Path | All state mutations flow through DialogueStateManager interface |
| R15 â€” Open/Closed | New conversation phases, intent types, and topic classifiers added via config, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Conversation/000-Overview.md | Dialogue State is a sub-component of Conversation OS; Session Manager owns state lifecycle |
| Memory/001-Working-Memory.md | Dialogue State reads from and writes to Working Memory for intent parameters |
| Memory/002-Episodic-Memory.md | Archived Dialogue State serialized to Episodic Memory for cross-session continuation |
| Brain/Context/000-Overview.md | Dialogue State is pushed into the context window for Sou's awareness |
| Brain/Sou/000-Overview.md | Sou reads Dialogue State to understand conversation progress and user intent |
| Brain/Attention/000-Overview.md | Topic shifts and intent changes generate attention signals |
| Brain/Planning/000-Overview.md | Plans reference the current conversation phase and flow constraints |
| Bible/05-Platform/004-EVS.md | All Dialogue State events recorded via Event System |
| Physics/009-Interaction.md | Dialogue State implements the Interaction Physics model |
