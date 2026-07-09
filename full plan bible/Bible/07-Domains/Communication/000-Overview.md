# AIOS Bible — Domains
## Communication — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-COM-000 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Communication domain enables AIOS to interact with human users through natural language — chat, messaging, voice, and multimodal interfaces. It provides the capability set for conversational agents, support bots, notification systems, and collaborative communication tools that bridge human intent and AIOS execution.

Unlike other domains that focus on machine-to-machine operations, Communication is human-facing. It deals with language understanding, dialogue state management, personalization, tone adaptation, and the translation of ambiguous human requests into structured AIOS goals that Sou can process.

## Domain Entities

The Communication domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| ChatWorker | A Worker specialized for conversational interaction | AGS: Communication/ChatWorker |
| SupportAgent | A Worker specialized for user support and triage | AGS: Communication/SupportAgent |
| NotificationDispatcher | A Worker that routes notifications to users | AGS: Communication/Notifier |
| DialogueSession | A persistent multi-turn conversation context | LMS: Session |
| UserPreference | A knowledge artifact storing user communication preferences | Academy: Knowledge |

## Capabilities

The Communication domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Chat | `process_message`, `maintain_context`, `detect_intent`, `generate_reply` | High token (LLM), medium latency |
| Translation | `translate_text`, `detect_language`, `localize_response` | Medium token, low compute |
| Summarization | `summarize_conversation`, `extract_key_points`, `generate_transcript` | High token, medium compute |
| Notification | `send_alert`, `schedule_reminder`, `batch_digest`, `priority_routing` | Low token, low compute |
| Sentiment Analysis | `analyze_tone`, `detect_urgency`, `assess_satisfaction` | Low token, low compute |
| Moderation | `filter_content`, `check_policy_violation`, `sanitize_input` | Medium token, low compute |
| Multimodal | `process_image_input`, `handle_voice`, `interpret_document` | High token, high compute |

## Conversation Lifecycle

A Conversation in the Communication domain follows this lifecycle:

```
Initiated → Context Established → Active ↔ Waiting → Resolved → Archived
```

| State | Description | Worker State |
|-------|-------------|--------------|
| Initiated | User sends first message | Created |
| Context Established | Intent identified, session initialized | Planned |
| Active | Ongoing exchange, Workers responding | Running |
| Waiting | User idle or pending external input | Waiting |
| Resolved | Goal achieved or user satisfied | Completed |
| Archived | Conversation record stored | Archived |

## Intent Resolution Pipeline

When a user message arrives, the Communication domain resolves intent through this pipeline:

```
1. Message received via ACF (from chat gateway, API, or federation bridge)
2. Sentiment and urgency analysis
3. Intent classification (request, question, command, report, feedback)
4. Entity extraction (users, resources, actions, constraints)
5. Context assembly (current dialogue + user history + preferences)
6. Goal formulation (structured goal for Sou)
7. Goal routing to Sou via DGP
8. Response generation when Sou returns decision/acknowledgment
9. Response delivery through appropriate channel
10. Conversation state updated
```

## Invariants

1. **COM-I-001 — Every Message Is Authenticated**: Every incoming and outgoing message is authenticated per Law 5 (Identity). Anonymous messages are rejected at the gateway.

2. **COM-I-002 — Context Preservation**: Conversation context is preserved across turns within a session. Context loss is a constitutional violation — the user must never need to repeat information.

3. **COM-I-003 — Response Bounded**: Responses are bounded by the Worker's capability scope. A ChatWorker may not generate responses outside its authorized domain.

4. **COM-I-004 — Privacy Preservation**: User conversation data is access-controlled per Organization policy. Cross-Organization conversation access requires explicit authorization.

5. **COM-I-005 — Intent Routing**: Every message has exactly one resolved intent. Ambiguous intents are resolved through clarification before routing to Sou.

## Edge Cases

| Scenario | Handling |
|----------|----------|
| User message contains multiple intents | Primary intent selected via confidence scoring. Secondary intents queued for follow-up. |
| Conversation context exceeds window limit | Context summarized by oldest-to-newest trimming. Key entities preserved. |
| User is inactive beyond timeout | Session marked as Idle. Preservation timeout applied before archival. |
| Incoming message fails moderation | Message rejected with policy violation notice. Moderation Event produced for Security Council. |
| Response generation exceeds latency SLO | Fallback response delivered ("I'm processing your request"). Background generation continues. |
| Channel adapter unavailable | Messages queued with TTL. If channel remains unavailable, notification sent via alternate channel. |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Comm.MessageReceived` | User message arrives | message_id, user_id, channel, message_type, intent, timestamp |
| `Comm.MessageSent` | Response is delivered to user | message_id, recipient, channel, response_time_ms, token_count |
| `Comm.IntentResolved` | User intent is classified | message_id, intent_category, confidence, entities, alternatives |
| `Comm.SentimentAnalyzed` | Sentiment analysis completes | message_id, sentiment_score, urgency_score, tone |
| `Comm.ConversationStarted` | New conversation session begins | session_id, user_id, channel, start_time, user_preference_hash |
| `Comm.ConversationResolved` | Conversation goal is achieved | session_id, outcome, turns_count, satisfaction_score, resolution_path |
| `Comm.NotificationSent` | Notification is dispatched | notification_id, recipient, priority, channel, delivery_status |

## Cross-Cutting Concerns

### Security

Communication Workers handle user-identifiable information. All conversation data is access-controlled per Organization policy. Messages are sanitized for injection attacks. Authentication is required for all incoming messages via ATS. User identity is verified through IDS before session establishment. (Physics/008-Security.md)

### Evidence

Every message, intent resolution, and conversation event produces an Event. Conversations are fully replayable from the Event stream for audit and learning. User satisfaction scores are derived from conversation evidence. (PHI-008)

### Lifecycle

Conversations follow a defined lifecycle managed by LMS. Chat Workers follow the canonical Worker lifecycle. Long-running conversations may span multiple Worker sessions through state handoff. Idle conversations are timed out per policy. (Physics/006-Lifecycles.md)

### Capability Bounds

Communication capabilities are bounded by token budgets per conversation, context window limits, and response time SLAs. A ChatWorker cannot exceed its authorized capability scope — it may not execute commands outside its designated domain. Language support is bounded by loaded language models. (Physics/007-Capabilities.md)

### Communication

The Communication domain both consumes and provides communication services. Internally, all communication flows through ACF (Law 3). Externally, Communication Workers interface with chat platforms, email gateways, voice systems, and API endpoints through adapters registered as resource providers. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each communication capability (chat, notify, moderate, translate) is a separate concern |
| R3 (DRY) | User preferences and conversation context are stored once, referenced by session |
| R6 (DI) | Chat platforms are injected as channel adapters — no hard coupling |
| R9 (Deterministic) | Intent classification with same input produces same classification |
| R10 (Simpler Over Complex) | Conversation state machine is linear — no branching complexity |
| R13 (Design for Failure) | Failed response generation returns graceful fallback message; conversation continues |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture — Communication domain structure |
| Physics/005-Events.md | Evidence — Communication operations produce Events |
| Physics/007-Capabilities.md | Capabilities — Communication capability bounds |
| Physics/009-Interaction.md | Interaction — Communication domain implements human-AIOS interaction patterns |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — Intent resolution feeds Sou reasoning |
| Bible/02-Core/AGS/000-Overview.md | AGS — ChatWorker and SupportAgent Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy — User preference learning and conversation analytics |
| Bible/06-Services/ACF/000-Overview.md | ACF — Communication transport for all domain operations |
| Bible/04-Execution/Security/ATS/000-Auth-Methods.md | ATS — User authentication for message ingress |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
