# AIOS Master API Specification

> **Purpose:** Single-source-of-truth registry for every concrete API endpoint, ACF topic, RPC method, streaming channel, interface method, and event type across the entire AIOS platform.
> **Framework Spec:** `Bible/08-Interfaces/API/000-Specifications.md` (API design conventions, versioning, error schemas)
> **Status:** Registry — catalogs what exists; does not prescribe design.

---

## Table of Contents

1. [Platform Services](#1-platform-services)
2. [Core Engines](#2-core-engines)
3. [Brain](#3-brain)
4. [Security Council](#4-security-council)
5. [Institutions](#5-institutions)
6. [Runtime](#6-runtime)
7. [Domains](#7-domains)
8. [Federation](#8-federation)
9. [Governance](#9-governance)
10. [Cross-Cutting](#10-cross-cutting)
11. [Appendix: Schema Index](#11-appendix-schema-index)

---

## 1. Platform Services

### 1.1 PSAP — Platform Service Access Point

**Source:** `Bible/05-Platform/003-PSAP.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `registerService(service_name, endpoint, capabilities, config)` | Service token | Register a service with the platform |
| 2 | `deregisterService(registration_id)` | Service token | Deregister a service |
| 3 | `resolveService(service_name, capabilities?, filter?)` | ACF-level | Resolve service name to endpoint |
| 4 | `resolveServiceBatch(service_name, count)` | ACF-level | Resolve multiple service instances |
| 5 | `getServiceHealth(service_name)` | ACF-level | Get health status for all instances of a service |
| 6 | `getServiceHealthByInstance(registration_id)` | ACF-level | Get health for a specific instance |
| 7 | `listServices(filter?)` | ACF-level | List all registered services |
| 8 | `getServiceMetrics(registration_id)` | ACF-level | Get metrics for a service instance |
| 9 | `updateServiceCapabilities(registration_id, capabilities)` | Service token | Update declared capabilities |
| 10 | `updateServiceLoad(registration_id, load)` | Service token | Update current load metric |

#### Messages

| # | Message | Auth | Description |
|---|---------|------|-------------|
| 11 | `PSAP.HealthCheck` | mTLS | Health check ping |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 12 | `PSAP.ServiceRegistered` | Service registered |
| 13 | `PSAP.ServiceDeregistered` | Service deregistered |
| 14 | `PSAP.ServiceHealthChanged` | Service health status changed |
| 15 | `PSAP.ServiceUnavailable` | All instances of a service become unhealthy |
| 16 | `PSAP.HeartbeatReceived` | Heartbeat received from service |
| 17 | `PSAP.RoutingUpdated` | Routing table modified |
| 18 | `PSAP.LoadBalanced` | Load balancing decision made |

---

### 1.2 EVS — Event Store

**Source:** `Bible/05-Platform/004-EVS.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 19 | `appendEvent(stream_id, event_type, data, metadata)` | ACF token | Append event to stream |
| 20 | `readStream(stream_id, from_version?, to_version?)` | ACF token | Read events from stream |
| 21 | `readStreamByTime(stream_id, from_time, to_time)` | ACF token | Read events by time range |
| 22 | `readEvent(event_id)` | ACF token | Read specific event by ID |
| 23 | `readEventByVersion(stream_id, version)` | ACF token | Read specific event version |
| 24 | `subscribeStream(stream_id, subscriber)` | ACF token | Subscribe to event stream |
| 25 | `queryEvents(query)` | ACF token | Query events by filter |
| 26 | `queryEventsByType(event_type, from_time, to_time)` | ACF token | Query events by type and time range |
| 27 | `getEventCount(stream_id)` | ACF token | Get event count |
| 28 | `getStreamInfo(stream_id)` | ACF token | Get stream info |
| 29 | `listStreams(filter?)` | ACF token | List all streams |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 30 | `EVS.EventAppended` | Event written to stream |
| 31 | `EVS.StreamCreated` | Event stream initialized |
| 32 | `EVS.SnapshotCreated` | Snapshot taken |
| 33 | `EVS.SubscriptionActivated` | Subscriber subscribed to stream |
| 34 | `EVS.SubscriptionEnded` | Subscriber unsubscribed |
| 35 | `EVS.ReadReplicaAdded` | Read replica came online |
| 36 | `EVS.RaftLeaderElected` | New Raft leader elected |
| 37 | `EVS.RetentionTriggered` | Events moved to cold storage |

---

### 1.3 EPG — Event Processing Graph

**Source:** `Bible/05-Platform/006-EPG.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 38 | Stream | Event Processing Graph (EPG) | ACF-level | DAG-based event stream processing (filter, transform, enrich, aggregate, route) |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 39 | `EPG.GraphDefined` | New processing graph defined |
| 40 | `EPG.GraphActivated` | Graph begins processing |
| 41 | `EPG.GraphDeactivated` | Graph stops processing |
| 42 | `EPG.GraphUpdated` | Graph definition modified |
| 43 | `EPG.NodeProcessed` | Graph node completed processing |
| 44 | `EPG.NodeFailed` | Node fails processing |
| 45 | `EPG.EventDeadLettered` | Event exceeds retry limit |
| 46 | `EPG.EnrichmentCacheHit` | Enrichment served from cache |
| 47 | `EPG.EnrichmentCacheMiss` | Enrichment fetched from source |

---

### 1.4 EIP — External Integration Protocol

**Source:** `Bible/05-Platform/007-EIP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 48 | Interface | `Connector` | N/A | All EIP connectors implement this interface |
| 49 | REST/gRPC/AMQP/MQTT | External Integration Protocol | mTLS (varies) | Protocol for webhook, Kafka, MQTT, AMQP, REST, gRPC connectors |

#### Messages

| # | Message | Description |
|---|---------|-------------|
| 50 | `ConnectorConfig` | Protocol, endpoint, format, authentication config |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 51 | `EIP.ConnectorCreated` | Connector defined |
| 52 | `EIP.ConnectorActivated` | Connector starts processing |
| 53 | `EIP.ConnectorDeactivated` | Connector stops |
| 54 | `EIP.ConnectorFailed` | Connector error |
| 55 | `EIP.ConnectorReconnected` | Connector re-establishes connection |
| 56 | `EIP.ConnectorArchived` | Connector decommissioned |
| 57 | `EIP.EventExported` | Event sent to external system |
| 58 | `EIP.EventImported` | Event received from external system |
| 59 | `EIP.SecurityViolation` | Security rule violated |
| 60 | `EIP.CircuitBreakerTripped` | Circuit breaker opens |

---

### 1.5 CP — Credential Provider

**Source:** `Bible/05-Platform/012-CP.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 61 | Interface | `Credential` | All credential types implement this |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 62 | `CP.CredentialRequested` | Credential is requested |
| 63 | `CP.CredentialApproved` | Request is approved |
| 64 | `CP.CredentialIssued` | Credential is generated |
| 65 | `CP.CredentialActivated` | Credential becomes active |
| 66 | `CP.CredentialRotated` | Credential is rotated |
| 67 | `CP.CredentialRevoked` | Credential is revoked |
| 68 | `CP.CredentialExpired` | Credential expires |
| 69 | `CP.RotationScheduled` | Rotation is scheduled |
| 70 | `CP.ValidationFailed` | Credential fails validation |

---

### 1.6 Graph Framework

**Source:** `Bible/05-Platform/013-Graph-Framework.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 71 | Interface | `GraphStore` | N/A | All graph storage backends implement this |
| 72 | RPC (ACF) | Graph Framework operations | ACF-level | Graph queries via ACF |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 73 | `GF.GraphCreated` | New graph created |
| 74 | `GF.GraphDeleted` | Graph removed |
| 75 | `GF.GraphCleared` | Graph content cleared |
| 76 | `GF.NodeAdded` | Node added to graph |
| 77 | `GF.NodeRemoved` | Node removed |
| 78 | `GF.EdgeAdded` | Edge added |
| 79 | `GF.EdgeRemoved` | Edge removed |
| 80 | `GF.QueryExecuted` | Query run |
| 81 | `GF.AnalysisCompleted` | Analysis operation done |

---

### 1.7 LMS — Lifecycle Management Service

**Source:** `Bible/05-Platform/000-LMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 82 | RPC (ACF) | LMS transition requests | ACF token | Entity lifecycle state transitions via ACF |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 83 | `LMS.EntityCreated` | Entity created |
| 84 | `LMS.StateChanged` | Entity state transitioned |
| 85 | `LMS.TransitionDenied` | State transition denied |
| 86 | `LMS.EntityCompleted` | Entity lifecycle completed |
| 87 | `LMS.EntityArchived` | Entity archived |
| 88 | `LMS.CascadeTriggered` | Parent triggers child cascade |
| 89 | `LMS.SnapshotCreated` | Snapshot persisted |

---

## 2. Core Engines

### 2.1 Academy — Knowledge Management

**Source:** `Bible/02-Core/Academy/016-Knowledge-API.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 90 | `academy.knowledge.create` | `knowledge.propose` | Propose a new knowledge artifact |
| 91 | `academy.knowledge.validate` | `knowledge.validate` | Trigger validation of knowledge artifact |
| 92 | `academy.knowledge.accept` | `knowledge.accept` | Accept validated knowledge into Registry |
| 93 | `academy.knowledge.query` | `knowledge.query` | Query knowledge artifacts by graph traversal |
| 94 | `academy.knowledge.search` | `knowledge.query` | Full-text, semantic, or faceted search |
| 95 | `academy.knowledge.get` | `knowledge.query` | Retrieve specific knowledge artifact by ID |
| 96 | `academy.knowledge.provenance` | `knowledge.query` | Get full provenance chain for artifact |
| 97 | `academy.knowledge.list` | `knowledge.query` | List knowledge artifacts with filters |
| 98 | `academy.knowledge.deprecate` | `knowledge.deprecate` | Deprecate a knowledge artifact |
| 99 | `academy.knowledge.compose` | `knowledge.compose.{method}` | Request KCE knowledge composition |
| 100 | `academy.knowledge.execute` | `knowledge.execute.{type}` | Request KEE knowledge execution |

#### Pub-Sub (ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 101 | `academy.knowledge.subscribe` | `knowledge.subscribe` | Subscribe to knowledge lifecycle events |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 102 | `API.RequestReceived` | API received a request |
| 103 | `API.RequestCompleted` | API completed processing |
| 104 | `API.RequestFailed` | API encountered an error |
| 105 | `API.RateLimitExceeded` | Rate limit exceeded |
| 106 | `API.SubscriptionCreated` | Subscription created |
| 107 | `API.SubscriptionRemoved` | Subscription removed |

---

### 2.2 Academy — Knowledge Search (REST Gateway)

**Source:** `Bible/02-Core/Academy/010-Knowledge-Search.md`

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 108 | `GET /search?q=...&fields=...&operator=...` | JWT | Full-text knowledge search |
| 109 | `GET /search?q=...&type=semantic&top_k=...` | JWT | Semantic knowledge search |
| 110 | `GET /search?type=graph&start_node_id=...&edge_types=...&max_depth=...` | JWT | Graph-based knowledge search |
| 111 | `GET /search?type=operational&organization_id=...&tags=...&confidence_min=...` | JWT | Faceted/operational knowledge search |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 112 | `Search.QueryExecuted` | Search query is executed |
| 113 | `Search.ResultClicked` | Consumer selects a search result |
| 114 | `Search.IndexUpdated` | Search index is updated |
| 115 | `Search.IndexRebuilt` | Full index rebuild completes |
| 116 | `Search.RankingRecalculated` | Ranking weights are updated |

---

### 2.3 Academy — KMS Query Interface

**Source:** `Bible/02-Core/Academy/002-KMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 117 | RPC (ACF) | KMS query interface | ACF-level | Knowledge management storage and retrieval queries |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 118 | `KMS.ArtifactCreated` | New knowledge artifact created |
| 119 | `KMS.ArtifactUpdated` | Existing artifact updated |
| 120 | `KMS.ArtifactDeprecated` | Artifact deprecated |
| 121 | `KMS.ArtifactArchived` | Artifact archived |
| 122 | `KMS.SnapshotCreated` | Snapshot written for version chain |
| 123 | `KMS.QueryExecuted` | Query executed against KMS |

---

### 2.4 Academy — Knowledge SDK Provider Interface

**Source:** `Bible/02-Core/Academy/015-Knowledge-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 124 | `authenticate(entity_id, credentials)` | ACF token | Authenticate with ATS and obtain session token |
| 125 | `setIdentity(identity)` | ACF token | Set identity for subsequent operations |
| 126 | `getCurrentEntity()` | ACF token | Returns authenticated entity info |
| 127 | `hasCapability(capability)` | ACF token | Check if entity has a specific capability |
| 128 | `search(query, options)` | ACF token | Full-text and semantic search |
| 129 | `getKnowledge(id)` | ACF token | Retrieve artifact by ID |
| 130 | `listKnowledge(filters)` | ACF token | List artifacts matching filters |
| 131 | `getProvenance(id, options)` | ACF token | Get provenance chain |
| 132 | `queryGraph(query)` | ACF token | Graph traversal query |
| 133 | `subscribe(topic, callback)` | ACF token | Subscribe to knowledge events |
| 134 | `unsubscribe(subscriptionId)` | ACF token | Unsubscribe from events |
| 135 | `onKnowledgeAccepted(callback)` | ACF token | Convenience subscription for accepted events |
| 136 | `onKnowledgeDeprecated(callback)` | ACF token | Convenience subscription for deprecation events |
| 137 | `proposeKnowledge(artifact)` | ACF token | Submit knowledge for validation |
| 138 | `getProposalStatus(proposalId)` | ACF token | Check proposal status |
| 139 | `withdrawProposal(proposalId)` | ACF token | Withdraw a pending proposal |
| 140 | `resubmitKnowledge(proposalId, updatedArtifact)` | ACF token | Resubmit with revisions |
| 141 | `composeUnion(artifactIds)` | ACF token | Union composition |
| 142 | `composeIntersection(artifactIds)` | ACF token | Intersection composition |
| 143 | `composeAnalogy(sourceId, targetDomain)` | ACF token | Analogy composition |
| 144 | `composeInduction(artifactIds)` | ACF token | Induction composition |
| 145 | `composeDeduction(principleId, context)` | ACF token | Deduction composition |
| 146 | `getCompositionStatus(requestId)` | ACF token | Check composition request status |
| 147 | `executeKnowledge(knowledgeId, context)` | ACF token | Execute a knowledge artifact |
| 148 | `getExecutionStatus(executionId)` | ACF token | Check execution status |
| 149 | `cancelExecution(executionId)` | ACF token | Cancel a pending execution |
| 150 | `getExecutionResult(executionId)` | ACF token | Get execution result |

#### SDK Events

| # | Event | Description |
|---|-------|-------------|
| 151 | `SDK.Authenticated` | SDK successfully authenticates |
| 152 | `SDK.QueryExecuted` | SDK executes a query |
| 153 | `SDK.KnowledgeProposed` | SDK proposes knowledge |
| 154 | `SDK.EventSubscribed` | SDK subscribes to a topic |
| 155 | `SDK.EventReceived` | SDK receives an event |
| 156 | `SDK.ErrorEncountered` | SDK encounters an error |

---

## 3. Brain

### 3.1 Sou — Executive Intelligence

**Source:** `Bible/02-Core/Brain/Sou/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 157 | Interface | `SouIdentity` | Sou's persistent identity — name, purpose, history |
| 158 | Interface | `SouPersonality` | Sou's behavioral traits, values, communication style |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 159 | `Sou.InputReceived` | Input entered Sou's processing |
| 160 | `Sou.DecisionMade` | Sou made a strategic decision |
| 161 | `Sou.MissionCreated` | Sou created a mission |
| 162 | `Sou.ResponseSent` | Sou sent a user-facing response |

---

### 3.2 LLMOS — AI Inference Pipeline

**Source:** `Bible/02-Core/Brain/LLMOS/`

#### RPC Methods (via ACF — `acf://llmos/inference`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 537 | `inference(request)` | Execution token | Full pipeline inference — non-streaming |
| 538 | `inferenceStream(request)` | Execution token | Full pipeline inference — streaming |
| 539 | `embed(inputs, model)` | Execution token | Generate embeddings |
| 540 | `countTokens(content, model)` | Execution token | Count tokens for content on specific model |
| 541 | `getModelStatus()` | ACF-level | Get status of all registered models |

#### Pipeline Events (Gateway)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 542 | `LLMOS.RequestReceived` | 000-Overview.md | Request entered pipeline |
| 543 | `LLMOS.SecurityChecked` | 000-Overview.md | Security Council verification passed |
| 544 | `LLMOS.RateChecked` | 000-Overview.md | Rate limit check passed |
| 545 | `LLMOS.BudgetChecked` | 006-Token-Budget-Manager.md | Token budget verified |
| 546 | `LLMOS.BudgetReconciled` | 006-Token-Budget-Manager.md | Budget reconciled after request |
| 547 | `LLMOS.RequestCompleted` | 000-Overview.md | Pipeline completed successfully |
| 548 | `LLMOS.RequestFailed` | 000-Overview.md | Pipeline failed |

#### Pipeline Events (Pre-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 549 | `LLMOS.ModelsResolved` | 001-Model-Registry.md | Model candidates matched requirements |
| 550 | `LLMOS.ModelSelected` | 002-Router.md | Router selected optimal model |
| 551 | `LLMOS.ModelRegistered` | 001-Model-Registry.md | New model registered |
| 552 | `LLMOS.ModelDeregistered` | 001-Model-Registry.md | Model deregistered |
| 553 | `LLMOS.ModelUpdated` | 001-Model-Registry.md | Model health/metrics updated |
| 554 | `LLMOS.ProviderRegistered` | 013-Provider-SDK.md | Provider initialized |
| 555 | `LLMOS.ProviderDeregistered` | 013-Provider-SDK.md | Provider shut down |
| 556 | `LLMOS.ProviderHealthChanged` | 001-Model-Registry.md | Provider health transitioned |
| 557 | `LLMOS.CostOptimized` | 007-Cost-Optimizer.md | Cost estimation and optimization complete |
| 558 | `LLMOS.CacheHit` | 011-Cache.md | Cache lookup hit |
| 559 | `LLMOS.CacheMiss` | 011-Cache.md | Cache lookup miss |
| 560 | `LLMOS.CacheStored` | 011-Cache.md | Response cached |
| 561 | `LLMOS.CacheEvicted` | 011-Cache.md | Cache entry evicted |
| 562 | `LLMOS.ContextBuilt` | 004-Context-Builder.md | Context window assembled |
| 563 | `LLMOS.MemoryInjected` | 005-Memory-Injection.md | Memories injected into context |
| 564 | `LLMOS.PromptCompiled` | 003-Prompt-Compiler.md | Prompt compiled from template |
| 565 | `LLMOS.GuardrailChecked` | 010-Guardrails.md | Guardrail evaluation (input or output) |

#### Pipeline Events (Execution)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 566 | `LLMOS.ProviderCalled` | 009-Retry-Engine.md | Provider API call made |
| 567 | `LLMOS.ProviderRetry` | 009-Retry-Engine.md | Retry triggered on provider error |
| 568 | `LLMOS.CircuitBreakerOpened` | 009-Retry-Engine.md | Circuit breaker opened for model |
| 569 | `LLMOS.CircuitBreakerClosed` | 009-Retry-Engine.md | Circuit breaker closed for model |
| 570 | `LLMOS.StreamChunk` | 008-Streaming-Manager.md | Stream chunk emitted |
| 571 | `LLMOS.StreamCompleted` | 008-Streaming-Manager.md | Stream terminated |
| 572 | `LLMOS.StreamError` | 008-Streaming-Manager.md | Mid-stream error occurred |

#### Pipeline Events (Post-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 573 | `LLMOS.ResponseValidated` | 012-Response-Validator.md | Response passed validation |
| 574 | `LLMOS.ResponseValidationFailed` | 012-Response-Validator.md | Response failed validation |
| 575 | `LLMOS.ResponseValidationRetry` | 012-Response-Validator.md | Validation retry triggered |

#### Model Provider Interfaces (SDK)

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 576 | Interface | `ModelProvider` | 013-Provider-SDK.md | Interface for AI model providers |
| 577 | Method | `initialize(config)` | 013-Provider-SDK.md | Initialize provider with config |
| 578 | Method | `healthCheck()` | 013-Provider-SDK.md | Report provider health |
| 579 | Method | `shutdown()` | 013-Provider-SDK.md | Graceful shutdown |
| 580 | Method | `listModels()` | 013-Provider-SDK.md | List available models |
| 581 | Method | `execute(request)` | 013-Provider-SDK.md | Execute model inference |
| 582 | Method | `executeStream(request)` | 013-Provider-SDK.md | Execute streaming inference |
| 583 | Method | `embed(inputs, model)` | 013-Provider-SDK.md | Generate embeddings |
| 584 | Method | `countTokens(content, model)` | 013-Provider-SDK.md | Count tokens for content |

#### Schemas

| # | Schema | Source | Description |
|---|--------|--------|-------------|
| 585 | `InferenceRequest` | 000-Overview.md | Full LLMOS request envelope |
| 586 | `InferenceResponse` | 000-Overview.md | Full LLMOS response envelope |
| 587 | `LLMOSChunk` | 008-Streaming-Manager.md | Streaming chunk schema |
| 588 | `ModelRequirements` | 000-Overview.md | Model selection constraints |
| 589 | `MemoryConfig` | 000-Overview.md | Memory retrieval configuration |
| 590 | `CachePolicy` | 011-Cache.md | Cache read/write behavior |
| 591 | `ModelEntry` | 001-Model-Registry.md | Registered model record |
| 592 | `CompiledPrompt` | 003-Prompt-Compiler.md | Compiled prompt structure |
| 593 | `ContextPayload` | 004-Context-Builder.md | Context window payload |
| 594 | `RetryConfig` | 009-Retry-Engine.md | Retry and fallback configuration |
| 595 | `GuardrailRule` | 010-Guardrails.md | Guardrail rule definition |
| 596 | `ProviderRequest` | 013-Provider-SDK.md | Provider-level request format |
| 597 | `ProviderResponse` | 013-Provider-SDK.md | Provider-level response format |
| 598 | `ProviderError` | 013-Provider-SDK.md | Provider error structure |
| 599 | `EntityTokenBudget` | 006-Token-Budget-Manager.md | Entity token budget structure |
| 600 | `CostEstimate` | 007-Cost-Optimizer.md | Cost estimation structure |
| 601 | `PromptTemplate` | 003-Prompt-Compiler.md | Prompt template definition |

---

### 3.3 DTS — Decision & Trust Scoring

**Source:** `Bible/02-Core/DTS/001-Architecture.md`, `Bible/02-Core/DTS/003-Sim-Engines.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 160 | Interface | `DecisionEvaluator` | Interface for evaluating decisions |
| 161 | Interface | `EvaluationResult` | Interface for evaluation results |
| 162 | Interface | `TrustScorer` | Interface for trust scoring |
| 163 | Interface | `TrustScore` | Interface for trust score data |
| 164 | Interface | `SimEngine` | All simulation engines implement this |

---

### 3.4 ROS — Resource Orchestration

**Source:** `Bible/02-Core/ROS/008-Provider-SDK.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 165 | Interface | `ResourceProvider` | SDK interface that all resource providers must implement |

---

## 4. Security Council

### 8.1 ACF — Anticipatory Communication Fabric

**Source:** `Bible/06-Services/ACF/`

#### 3.1.1 Messaging (`002-Messages.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 166 | `sendMessage(envelope, payload)` | auth_token | Send a message |
| 167 | `sendMessageWithAck(envelope, payload, timeout)` | auth_token | Send with acknowledgement |
| 168 | `receiveMessage(entity_id, timeout?)` | auth_token | Receive a message |
| 169 | `getMessageStatus(message_id)` | auth_token | Get message delivery status |
| 170 | `retryMessage(message_id)` | auth_token | Retry failed message |
| 171 | `deadLetterMessage(message_id, reason)` | auth_token | Move to dead letter queue |
| 172 | `acknowledgeMessage(message_id)` | auth_token | Acknowledge message |
| 173 | `rejectMessage(message_id, reason)` | auth_token | Reject message |

#### 3.1.2 Routing (`003-Routing.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 174 | `defineRoute(target_pattern, endpoints, config)` | Security Council | Define routing rule |
| 175 | `updateRoute(route_id, updates)` | Security Council | Update routing rule |
| 176 | `removeRoute(route_id)` | Security Council | Remove routing rule |
| 177 | `resolveRoute(target, sender?)` | ACF-level | Resolve target to endpoint |
| 178 | `getRoute(route_id)` | ACF-level | Get route entry |
| 179 | `listRoutes(filter?)` | ACF-level | List routing entries |
| 180 | `testRoute(target, message?)` | ACF-level | Test route resolution |

#### 3.1.3 Subscriptions (`004-Subscriptions.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 181 | `subscribe(entity_id, topic_pattern, subscription_type, config)` | ACF-level | Subscribe to topic |
| 182 | `unsubscribe(subscription_id)` | ACF-level | Unsubscribe from topic |
| 183 | `publish(topic, message)` | ACF-level | Publish message to topic |
| 184 | `listSubscriptions(entity_id)` | ACF-level | List subscriptions |
| 185 | `listSubscribers(topic)` | ACF-level | List subscribers of topic |
| 186 | `getSubscriptionStatus(subscription_id)` | ACF-level | Get subscription status |
| 187 | `updateSubscription(subscription_id, updates)` | ACF-level | Update subscription configuration |

#### Canonical ACF Topic Names

| # | Topic Pattern | Description |
|---|--------------|-------------|
| 188 | `academy.knowledge.accepted` | Knowledge accepted events |
| 189 | `academy.knowledge.rejected` | Knowledge rejected events |
| 190 | `academy.knowledge.revised` | Knowledge revised events |
| 191 | `lifecycle.state.changed` | Lifecycle state changes |
| 192 | `lifecycle.entity.created` | Entity created |
| 193 | `lifecycle.entity.completed` | Entity completed |
| 194 | `security.auth.authenticated` | Auth success events |
| 195 | `security.auth.authorized` | Auth authorized events |
| 196 | `security.auth.denied` | Auth denied events |
| 197 | `system.session.created` | Session created |
| 198 | `system.session.destroyed` | Session destroyed |

#### 3.1.4 Streaming (`005-Streaming.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 199 | `createStream(topic, partitions, config)` | ACF-level | Create a stream |
| 200 | `deleteStream(stream_id)` | ACF-level | Delete a stream |
| 201 | `publishToStream(topic, message, partition_key?)` | ACF-level | Publish to stream |
| 202 | `publishToPartition(stream_id, partition_id, message)` | ACF-level | Publish to specific partition |
| 203 | `consumeStream(stream_id, consumer_group, consumer_id)` | ACF-level | Consume from stream |
| 204 | `getStreamPosition(consumer_group, consumer_id, partition_id?)` | ACF-level | Get stream position |
| 205 | `seekStream(consumer_group, consumer_id, position)` | ACF-level | Seek to position |
| 206 | `commitPosition(consumer_group, consumer_id, partition_id, sequence)` | ACF-level | Commit consumer position |
| 207 | `getStreamInfo(stream_id)` | ACF-level | Get stream info |
| 208 | `listStreams(filter?)` | ACF-level | List streams |

#### 3.1.5 Reliability / DLQ (`006-Reliability.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 209 | `configureRetry(topic_pattern, retry_policy)` | Security Council | Configure retry policy |
| 210 | `getRetryStatus(message_id)` | ACF-level | Get retry status |
| 211 | `getDeadLetterMessages(filter?)` | Security Council | List DLQ messages |
| 212 | `replayDeadLetter(dlq_message_id, new_target?)` | Security Council | Replay DLQ message |
| 213 | `replayAllDeadLetter(filter?)` | Security Council | Replay all DLQ messages |
| 214 | `purgeDeadLetter(filter?)` | Security Council | Purge DLQ messages |
| 215 | `getDeadLetterStats()` | Security Council | Get DLQ statistics |
| 216 | `getDeadLetterMessage(dlq_message_id)` | Security Council | Get specific DLQ message |

#### 3.1.6 Distributed / Instance Federation (`007-Distributed.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 217 | `connectInstance(instance_url, credentials, config)` | mTLS X.509 | Connect to remote ACF instance |
| 218 | `disconnectInstance(bridge_id)` | mTLS | Disconnect remote instance |
| 219 | `syncRoutingTable(bridge_id)` | mTLS | Sync routing tables |
| 220 | `getInstanceStatus(instance_id)` | mTLS | Get remote instance status |
| 221 | `listConnectedInstances()` | mTLS | List all connected instances |
| 222 | `updateBandwidth(bridge_id, bandwidth_bps)` | Security Council | Update bridge bandwidth |
| 223 | `updateExportPolicy(bridge_id, policy)` | Security Council | Update route export policy |

#### ACF Messages

| # | Message | Description |
|---|---------|-------------|
| 224 | `Message` (envelope + payload) | Fundamental unit of communication |
| 225 | `Envelope` | Routing and metadata (version, message_id, sender, target, timestamp, ttl, priority, delivery_mode) |
| 226 | `DeliveryStatus` | Message delivery status tracking |
| 227 | `DeliveryAttempt` | Delivery attempt record |
| 228 | `DeadLetterMessage` | Undeliverable message with failure metadata |
| 229 | `DeliveryFailure` | Delivery failure details |
| 230 | `RetryPolicy` | Retry policy configuration |

#### ACF Events

| # | Event | Source File | Description |
|---|-------|-------------|-------------|
| 231 | `ACF.MessageSent` | 002-Messages | Sender dispatches message |
| 232 | `ACF.MessageAuthenticated` | 002-Messages | Token verified |
| 233 | `ACF.MessageAuthorized` | 002-Messages | Route permitted |
| 234 | `ACF.MessageQueued` | 002-Messages | Message persisted |
| 235 | `ACF.MessageRouted` | 002-Messages | Target endpoint selected |
| 236 | `ACF.MessageDelivered` | 002-Messages | Message reaches receiver |
| 237 | `ACF.MessageAcknowledged` | 002-Messages | Receiver confirms |
| 238 | `ACF.MessageFailed` | 002-Messages | Permanent delivery failure |
| 239 | `ACF.MessageExpired` | 002-Messages | TTL exceeded |
| 240 | `ACF.RouteDefined` | 003-Routing | Route created |
| 241 | `ACF.RouteUpdated` | 003-Routing | Route modified |
| 242 | `ACF.RouteRemoved` | 003-Routing | Route deleted |
| 243 | `ACF.EndpointUnavailable` | 003-Routing | Endpoint becomes unhealthy |
| 244 | `ACF.EndpointRestored` | 003-Routing | Endpoint becomes healthy |
| 245 | `ACF.RouteUnresolvable` | 003-Routing | No route matches |
| 246 | `ACF.RoutingTableSynced` | 003-Routing | Routing table synchronized |
| 247 | `ACF.SubscriptionCreated` | 004-Subscriptions | Subscription created |
| 248 | `ACF.SubscriptionActivated` | 004-Subscriptions | Subscription activated |
| 249 | `ACF.SubscriptionPaused` | 004-Subscriptions | Subscription paused |
| 250 | `ACF.SubscriptionResumed` | 004-Subscriptions | Subscription resumed |
| 251 | `ACF.SubscriptionUnsubscribed` | 004-Subscriptions | Subscription ended |
| 252 | `ACF.MessagePublished` | 004-Subscriptions | Message published to topic |
| 253 | `ACF.SubscriptionDelivered` | 004-Subscriptions | Message delivered to subscriber |
| 254 | `ACF.BackpressureApplied` | 004-Subscriptions | Slow subscriber throttled |
| 255 | `ACF.FilterEvaluated` | 004-Subscriptions | Filter predicate evaluated |
| 256 | `ACF.StreamCreated` | 005-Streaming | Stream created |
| 257 | `ACF.StreamDeleted` | 005-Streaming | Stream deleted |
| 258 | `ACF.PartitionReassigned` | 005-Streaming | Partition reassigned |
| 259 | `ACF.ConsumerAdded` | 005-Streaming | Consumer joins group |
| 260 | `ACF.ConsumerRemoved` | 005-Streaming | Consumer leaves |
| 261 | `ACF.ConsumerRebalanced` | 005-Streaming | Group rebalanced |
| 262 | `ACF.StreamEnd` | 005-Streaming | Stream reaches end |
| 263 | `ACF.BackpressureApplied` | 005-Streaming | Backpressure triggered |
| 264 | `ACF.BackpressureOverflow` | 005-Streaming | Buffer overflow |
| 265 | `ACF.PositionCommitted` | 005-Streaming | Consumer commits position |
| 266 | `ACF.RetryPolicyConfigured` | 006-Reliability | Retry policy set |
| 267 | `ACF.DeliveryAttempted` | 006-Reliability | Delivery attempt made |
| 268 | `ACF.DeliverySucceeded` | 006-Reliability | Delivery succeeds |
| 269 | `ACF.DeliveryFailed` | 006-Reliability | Delivery fails |
| 270 | `ACF.MessageDeadLettered` | 006-Reliability | Message sent to DLQ |
| 271 | `ACF.DLQReplayed` | 006-Reliability | DLQ message replayed |
| 272 | `ACF.DLQPurged` | 006-Reliability | DLQ messages purged |
| 273 | `ACF.ReliabilityThresholdBreached` | 006-Reliability | Reliability target missed |
| 274 | `ACF.DLQReviewed` | 006-Reliability | DLQ review completed |
| 275 | `ACF.InstanceConnected` | 007-Distributed | ACF bridge established |
| 276 | `ACF.InstanceDisconnected` | 007-Distributed | Bridge torn down |
| 277 | `ACF.InstancePartitioned` | 007-Distributed | Network partition detected |
| 278 | `ACF.InstanceReconnected` | 007-Distributed | Partition healed |
| 279 | `ACF.RoutingTableSynced` | 007-Distributed | Routing tables synchronized |
| 280 | `ACF.CrossInstanceMessageSent` | 007-Distributed | Message crosses instance boundary |
| 281 | `ACF.CrossInstanceMessageReceived` | 007-Distributed | Message received from remote |
| 282 | `ACF.HopLimitExceeded` | 007-Distributed | Message exceeds max hops |
| 283 | `ACF.BandwidthExceeded` | 007-Distributed | Bandwidth limit hit |
| 284 | `ACF.ClusterNodeJoined` | 001-Architecture | New node joins ACF cluster |
| 285 | `ACF.ClusterNodeLeft` | 001-Architecture | Node leaves cluster |
| 286 | `ACF.ClusterLeaderElected` | 001-Architecture | New Raft leader elected |
| 287 | `ACF.TopicPartitionCreated` | 001-Architecture | Topic partition created |
| 288 | `ACF.TopicPartitionReassigned` | 001-Architecture | Partition reassigned |

---

### 8.2 AZS — Authorization Services

**Source:** `Bible/04-Execution/Security/AZS/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 289 | Interface | `Permission` | 000-RBAC.md | Permission definition interface |
| 290 | Interface | `ABACPolicy` | 001-ABAC.md | Attribute-based access control policy interface |
| 291 | Interface | `Capability` | 002-Capability.md | Capability token interface |

#### AZS Events

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 292 | `AZS.RoleCreated` | 000-RBAC.md | A new role is defined |
| 293 | `AZS.RoleAssigned` | 000-RBAC.md | A role is assigned to an entity |
| 294 | `AZS.RoleRevoked` | 000-RBAC.md | A role is revoked from an entity |
| 295 | `AZS.AuthorizationCheck` | 000-RBAC.md | An authorization decision is made |
| 296 | `AZS.PermissionDenied` | 000-RBAC.md | Authorization is denied |
| 297 | `AZS.RoleExpired` | 000-RBAC.md | A temporal role expires |
| 298 | `AZS.InheritanceViolation` | 000-RBAC.md | A cycle is detected in role hierarchy |
| 299 | `AZS.AttributeResolved` | 001-ABAC.md | An attribute value is resolved for evaluation |
| 300 | `AZS.PolicyEvaluated` | 001-ABAC.md | An ABAC policy is evaluated |
| 301 | `AZS.PolicyCreated` | 001-ABAC.md | A new ABAC policy is defined |
| 302 | `AZS.PolicyChanged` | 001-ABAC.md | An ABAC policy is modified |
| 303 | `AZS.PolicyActivated` | 001-ABAC.md | A policy transitions to Active |
| 304 | `AZS.PolicyConflict` | 001-ABAC.md | A conflict is detected between policies |
| 305 | `AZS.ABACOverride` | 001-ABAC.md | ABAC decision overrides RBAC decision |
| 306 | `AZS.CapabilityIssued` | 002-Capability.md | Capability created |
| 307 | `AZS.CapabilityPresented` | 002-Capability.md | Capability presented for verification |
| 308 | `AZS.CapabilityVerified` | 002-Capability.md | Capability passes verification |
| 309 | `AZS.CapabilityDenied` | 002-Capability.md | Capability fails verification |
| 310 | `AZS.CapabilityRevoked` | 002-Capability.md | Capability revoked |
| 311 | `AZS.CapabilityExpired` | 002-Capability.md | Capability expired |
| 312 | `AZS.DelegationExtended` | 002-Capability.md | Delegation extended |
| 313 | `AZS.CapabilityConsumed` | 002-Capability.md | One-time capability consumed |

---

### 8.3 SSM — Session & Secret Management

**Source:** `Bible/04-Execution/Security/SSM/000-SSM.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 314 | Interface | `Session` | Session model interface |
| 315 | Interface | `SessionToken` | Session token interface |
| 316 | Interface | `Secret` | Secret model interface |

#### SSM Events

| # | Event | Description |
|---|-------|-------------|
| 317 | `SSM.SessionCreated` | New session created |
| 318 | `SSM.SessionAuthenticated` | Session authenticated |
| 319 | `SSM.SessionTerminated` | Session terminated |
| 320 | `SSM.SessionSuspended` | Session suspended |
| 321 | `SSM.SessionRestored` | Session restored |
| 322 | `SSM.SessionTokenRefreshed` | Session token refreshed |
| 323 | `SSM.SecretGenerated` | New secret generated |
| 324 | `SSM.SecretRotated` | Secret rotated |
| 325 | `SSM.SecretRevoked` | Secret revoked |
| 326 | `SSM.SecretCompromised` | Secret compromised |
| 327 | `SSM.SecretDestroyed` | Secret destroyed |
| 328 | `SSM.SecretAccessDenied` | Secret access denied |

---

### 8.4 EAS — Evidence & Audit Service

**Source:** `Bible/04-Execution/Security/Audit/000-EAS.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 329 | Interface | `EvidenceRecord` | Evidence record structure |
| 330 | Interface | `EvidenceQuery` | Evidence query interface |
| 331 | Interface | `ChainVerificationResult` | Chain verification result |

#### EAS Events

| # | Event | Description |
|---|-------|-------------|
| 332 | `EAS.EvidenceSealed` | Evidence record sealed |
| 333 | `EAS.ChainExtended` | Merkle-DAG chain extended |
| 334 | `EAS.ChainVerified` | Chain verification completed |
| 335 | `EAS.RetentionApplied` | Evidence archived per retention |
| 336 | `EAS.IntegrityAlert` | Chain integrity check fails |
| 337 | `EAS.BulkExportInitiated` | Bulk evidence export begins |
| 338 | `EAS.EvidenceArchived` | Evidence archived to cold storage |

---

### 8.5 CSP — Cryptography Service Provider

**Source:** `Bible/04-Execution/Security/Crypto/000-CSP.md`, `Bible/06-Services/Cryptography/000-CSP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 339 | Interface | `SigningRequest` | N/A | CSP signing request |
| 340 | Interface | `SigningResult` | N/A | CSP signing result |
| 341 | Interface | `VerificationRequest` | N/A | CSP verification request |
| 342 | Interface | `VerificationResult` | N/A | CSP verification result |
| 343 | RPC (ACF) | CSP operations | mTLS | All cryptographic operations via ACF |

#### CSP Events

| # | Event | Description |
|---|-------|-------------|
| 344 | `CSP.KeyGenerated` | A new cryptographic key is generated |
| 345 | `CSP.KeyActivated` | A key transitions to Active |
| 346 | `CSP.KeyRotated` | A key is rotated |
| 347 | `CSP.KeySuspended` | A key is suspended |
| 348 | `CSP.KeyCompromised` | A key is reported compromised |
| 349 | `CSP.KeyDestroyed` | A key is cryptographically destroyed |
| 350 | `CSP.SigningOperation` | A signing operation is performed |
| 351 | `CSP.VerificationOperation` | A verification operation is performed |
| 352 | `CSP.PolicyViolation` | A cryptographic operation violates policy |
| 353 | `CSP.HSMAudit` | HSM generates an audit event |

---

### 8.6 TLM — Trust Level Manager

**Source:** `Bible/04-Execution/Security/Trust/000-TLM.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 354 | Interface | `TrustScore` | Trust score model |

---

### 8.7 Policy System

**Source:** `Bible/04-Execution/Security/Policy-System/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 355 | Interface | `Policy` | 000-PS.md | Policy definition interface |
| 356 | Interface | `ValidationReport` | 002-PVE.md | Policy validation report |

---

### 8.8 Risk Engine

**Source:** `Bible/04-Execution/Security/Risk/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 357 | Interface | `RiskScore` | 000-RE.md | Risk score model |
| 358 | Interface | `AREAttribution` | 002-ARE.md | Advanced risk engine attribution |

---

### 8.9 Execution Auth Pipeline

**Source:** `Bible/04-Execution/Security/Execution-Auth/000-EAS.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 359 | Interface | `PipelineContext` | Verification pipeline context |

---

### 4.10 Sandbox / Isolation

**Source:** `Bible/04-Execution/Security/Sandbox/000-Isolation.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 360 | Interface | `SandboxLimits` | Sandbox resource limits |

---

### 4.11 IDS — Identity Provenance

**Source:** `Bible/04-Execution/Security/IDS/005-Provenance.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 361 | Interface | `ProvenanceChain` | Identity provenance chain |

---

## 5. Institutions

### 8.1 WCS — Worker Communication Service

**Source:** `Bible/03-Institutions/Workers/004-WCS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 362 | RPC | `sendMessage(sender_id, target_id, message_type, payload)` | Capability-based | Send message from one Worker to another |
| 363 | RPC | `broadcastMessage(sender_id, mission_id, message_type, payload)` | Capability-based | Broadcast message to all Workers in mission |
| 364 | RPC | `publishMessage(sender_id, topic, payload)` | Capability-based | Publish message to topic |
| 365 | RPC | `sendMessageWithResponse(...)` | Capability-based | Send message and wait for response |
| 366 | RPC | `receiveMessage(session_id, message_id?)` | Capability-based | Dequeue next message |
| 367 | RPC | `subscribeTopic(session_id, topic, filter_criteria?)` | Capability-based | Subscribe to a topic |
| 368 | RPC | `unsubscribeTopic(subscription_id)` | Capability-based | Unsubscribe from a topic |
| 369 | RPC | `getMessageHistory(session_id, time_range, filters?)` | Capability-based | Query message history |
| 370 | RPC | `getPendingMessages(session_id)` | Capability-based | List undelivered messages |
| 371 | Interface | `MessageChannel` | N/A | All communication patterns implement this |
| 372 | Message | `WorkerMessage` | N/A | message_id, sender_id, target_id, message_type, payload, ttl |

#### WCS Events

| # | Event | Description |
|---|-------|-------------|
| 373 | `WCS.MessageSent` | Worker sends a message |
| 374 | `WCS.MessageDelivered` | Message reaches target |
| 375 | `WCS.MessageFailed` | Message delivery fails |
| 376 | `WCS.MessageExpired` | Message TTL exceeded |
| 377 | `WCS.MessageDropped` | Queue overflow message dropped |
| 378 | `WCS.MessageAuthorizationDenied` | Cross-scope message denied |
| 379 | `WCS.SubscriptionCreated` | Worker subscribes to a topic |
| 380 | `WCS.SubscriptionRemoved` | Worker unsubscribes |
| 381 | `WCS.BroadcastSent` | Broadcast message transmitted |

---

### 8.2 WSS — Worker Security Service

**Source:** `Bible/03-Institutions/Workers/003-WSS.md`

| # | Event | Description |
|---|-------|-------------|
| 382 | `WSS.IsolationViolation` | Worker violates isolation boundary |
| 383 | `WSS.BoundaryCrossingAttempt` | Worker attempts cross-boundary access |
| 384 | `WSS.ResourceExhaustion` | Worker exceeds resource quota |
| 385 | `WSS.CapabilityViolation` | Worker attempts action outside capability scope |
| 386 | `WSS.IsolationConfigured` | Worker isolation configuration changed |
| 387 | `WSS.IsolationValidated` | Isolation layers are verified |
| 388 | `WSS.BoundaryEnforced` | Enforcement action taken on boundary violation |
| 389 | `WSS.CommunicationSpoofAttempt` | Worker attempts to spoof another Worker's identity |

---

### 8.3 Playbook Manager

**Source:** `Bible/03-Institutions/Workers/005-Playbook-Manager.md`

| # | Event | Description |
|---|-------|-------------|
| 390 | `PLAYBOOK.Created` | New playbook is created |
| 391 | `PLAYBOOK.Validated` | Playbook passes validation |
| 392 | `PLAYBOOK.Published` | Playbook is published |
| 393 | `PLAYBOOK.Deprecated` | Playbook is deprecated |
| 394 | `PLAYBOOK.Archived` | Playbook is archived |
| 395 | `PLAYBOOK.ExecutionStarted` | Playbook execution begins |
| 396 | `PLAYBOOK.ExecutionApproved` | Execution request is approved |
| 397 | `PLAYBOOK.ExecutionRejected` | Execution request is denied |
| 398 | `PLAYBOOK.StepCompleted` | Individual step finishes |
| 399 | `PLAYBOOK.StepFailed` | Step encounters error |
| 400 | `PLAYBOOK.RollbackInitiated` | Rollback plan begins execution |
| 401 | `PLAYBOOK.RollbackCompleted` | Rollback finishes |
| 402 | `PLAYBOOK.ExecutionCompleted` | Playbook execution finishes successfully |
| 403 | `PLAYBOOK.ExecutionFailed` | Execution fails (unrecoverable) |
| 404 | `PLAYBOOK.ExecutionCancelled` | Execution is cancelled mid-run |

---

### 8.4 OIS — Organization Interaction Service

**Source:** `Bible/03-Institutions/Organizations/006-OIS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 405 | Interface | `InteractionChannel` | N/A | All communication patterns implement this |
| 406 | ACF Topic | `org.research.findings` | ACF | Cross-Organization research findings subscription |
| 407 | ACF Topic | Org-wide broadcast topic | ACF | Cross-Organization broadcast |

#### OIS Events

| # | Event | Description |
|---|-------|-------------|
| 408 | `OIS.RequestSent` | Cross-Org request is sent |
| 409 | `OIS.RequestResponded` | Request receives response |
| 410 | `OIS.RequestDeclined` | Request is declined |
| 411 | `OIS.SubscriptionCreated` | Org subscribes to a topic |
| 412 | `OIS.SubscriptionRemoved` | Org unsubscribes |
| 413 | `OIS.AgreementReached` | Cross-Org agreement is finalized |
| 414 | `OIS.AgreementExpired` | Cross-Org agreement expires |
| 415 | `OIS.KnowledgeShared` | Knowledge is shared between Orgs |
| 416 | `OIS.AuthorizationDenied` | Cross-Org message authorization fails |

---

## 6. Runtime

### 8.1 Execution Runtime SDK

**Source:** `Bible/04-Execution/Runtime/001-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 417 | Interface | `ExecutionProvider` | Execution token | Interface all execution providers implement |
| 418 | Method | `providerId()` | N/A | Returns provider identity |
| 419 | Method | `providerVersion()` | N/A | Returns provider version |
| 420 | Method | `supportedActionTypes()` | N/A | Returns supported action types |
| 421 | Method | `capabilityDeclaration()` | N/A | Returns capability declaration |
| 422 | Method | `initialize(config)` | N/A | Initialize provider with configuration |
| 423 | Method | `health()` | N/A | Returns provider health status |
| 424 | Method | `shutdown()` | N/A | Graceful shutdown |
| 425 | Method | `execute(context)` | VerificationToken | Execute an action (core contract) |
| 426 | Method | `executeStream(context)` | VerificationToken | Streaming execution |

#### Runtime Messages / Types

| # | Type | Name | Description |
|---|------|------|-------------|
| 427 | Message | `ExecutionContext` | execution_id, token, action, capability_bounds, autonomy_level, parent_entity_id, deadline |
| 428 | Message | `ExecutionResult` | execution_id, status, output, metrics, error, events |
| 429 | Stream Chunk | `ExecutionChunk` | sequence, data, progress, is_final, metrics |

#### Runtime Events

| # | Event | Description |
|---|-------|-------------|
| 430 | `Runtime.ProviderRegistered` | Provider registered with Runtime Manager |
| 431 | `Runtime.ProviderHealthChanged` | Provider health status changes |
| 432 | `Runtime.ProviderExecutionStarted` | Provider execution starts |
| 433 | `Runtime.ProviderResourceWarning` | Provider resource warning |
| 434 | `Runtime.ProviderExecutionCompleted` | Provider execution completed |
| 435 | `Runtime.ProviderExecutionFailed` | Provider execution failed |
| 436 | `Runtime.ProviderBoundsExceeded` | Provider bounds exceeded |
| 437 | `Runtime.ProviderShutdown` | Provider shutdown |

---

### 8.2 Ollama Integration

**Source:** `Bible/04-Execution/Runtime/004-Ollama.md`

| # | Type | Endpoint | Auth | Description |
|---|------|----------|------|-------------|
| 438 | REST | `POST {endpoint}/api/generate` | Network-bound (localhost/private) | Ollama model generation endpoint |
| 439 | REST | `POST {endpoint}/api/chat` | Network-bound (localhost/private) | Ollama chat endpoint |

---

### 8.3 Runtime SDK (Interface Layer)

**Source:** `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 440 | Interface | `RuntimeProvider` | mTLS | Interface for runtime execution providers |
| 441 | Method | `createSession(genome, allocation)` | Execution token | Create Worker session |
| 442 | Method | `startSession(sessionId)` | Execution token | Start session |
| 443 | Method | `pauseSession(sessionId)` | Execution token | Pause session |
| 444 | Method | `resumeSession(sessionId)` | Execution token | Resume session |
| 445 | Method | `terminateSession(sessionId)` | Execution token | Terminate session |
| 446 | Method | `invokeCapability(sessionId, capability, input)` | Execution token | Execute capability |
| 447 | Method | `cancelInvocation(sessionId, invocationId)` | Execution token | Cancel invocation |
| 448 | Method | `getSessionStatus(sessionId)` | Execution token | Query session state |
| 449 | Method | `streamMetrics(sessionId)` | Execution token | Subscribe to metrics |
| 450 | Method | `healthCheck()` | N/A | Report provider health |
| 451 | Method | `reportUsage(sessionId)` | Execution token | Report resource usage |

#### ACF Endpoints

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 452 | `acf://runtime-provider-id/control` | ACF | Runtime provider control endpoint |
| 453 | `acf://runtime-provider-id/metrics` | ACF | Runtime provider metrics endpoint |
| 454 | `acf://runtime-provider-id/events` | ACF | Runtime provider events endpoint |

#### Runtime SDK Events

| # | Event | Description |
|---|-------|-------------|
| 455 | `SDK.RuntimeSessionCreated` | Runtime session created |
| 456 | `SDK.RuntimeSessionStarted` | Session transitions to Running |
| 457 | `SDK.RuntimeSessionPaused` | Session paused |
| 458 | `SDK.RuntimeSessionTerminated` | Session terminates |
| 459 | `SDK.RuntimeInvocationCompleted` | Capability invocation finishes |
| 460 | `SDK.RuntimeHealthChanged` | Provider health changes |
| 461 | `SDK.RuntimeUsageReported` | Resource usage reported |

---

### 8.4 Audit SDK

**Source:** `Bible/08-Interfaces/SDK/001-Audit-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 462 | `queryEvents(filter)` | audit scope | Query Events by filter criteria |
| 463 | `getEventById(eventId)` | audit scope | Retrieve single Event |
| 464 | `streamEvents(filter)` | audit scope | Subscribe to Event stream |
| 465 | `verifyChain(eventId)` | audit scope | Verify Event chain integrity |
| 466 | `verifyIntegrity(eventRange)` | audit scope | Verify Event range integrity |
| 467 | `computeHash(eventId)` | audit scope | Compute cryptographic hash |
| 468 | `analyzePattern(filter, pattern)` | audit scope | Detect patterns across Events |
| 469 | `computeAggregation(filter, metric)` | audit scope | Aggregate metrics |
| 470 | `detectAnomaly(filter, baseline)` | audit scope | Detect anomalous patterns |
| 471 | `checkCompliance(filter, standard)` | audit scope | Check compliance |
| 472 | `generateEvidencePackage(caseId, filter)` | audit scope | Generate evidence package |
| 473 | `produceReport(template, filter)` | audit scope | Produce audit report |
| 474 | `registerAsObserver()` | audit scope | Register as event observer |
| 475 | `setRetentionPolicy(policy)` | audit scope | Set retention policy |
| 476 | `getRetentionPolicy()` | audit scope | Get current retention policy |

---

### 8.5 LLMOS — LLM Operating System

**Source:** `Bible/04-Execution/LLMOS/`

#### LLMOS RPC Methods (via ACF — `acf://llmos/inference`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 537 | `inference(request)` | Execution token | Full pipeline inference — non-streaming |
| 538 | `inferenceStream(request)` | Execution token | Full pipeline inference — streaming |
| 539 | `embed(inputs, model)` | Execution token | Generate embeddings |
| 540 | `countTokens(content, model)` | Execution token | Count tokens for content on specific model |
| 541 | `getModelStatus()` | ACF-level | Get status of all registered models |

#### LLMOS Pipeline Events (Gateway)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 542 | `LLMOS.RequestReceived` | 000-Overview.md | Request entered pipeline |
| 543 | `LLMOS.SecurityChecked` | 000-Overview.md | Security Council verification passed |
| 544 | `LLMOS.RateChecked` | 000-Overview.md | Rate limit check passed |
| 545 | `LLMOS.BudgetChecked` | 006-Token-Budget-Manager.md | Token budget verified |
| 546 | `LLMOS.BudgetReconciled` | 006-Token-Budget-Manager.md | Budget reconciled after request |
| 547 | `LLMOS.RequestCompleted` | 000-Overview.md | Pipeline completed successfully |
| 548 | `LLMOS.RequestFailed` | 000-Overview.md | Pipeline failed |

#### LLMOS Pipeline Events (Pre-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 549 | `LLMOS.ModelsResolved` | 001-Model-Registry.md | Model candidates matched requirements |
| 550 | `LLMOS.ModelSelected` | 002-Router.md | Router selected optimal model |
| 551 | `LLMOS.ModelRegistered` | 001-Model-Registry.md | New model registered |
| 552 | `LLMOS.ModelDeregistered` | 001-Model-Registry.md | Model deregistered |
| 553 | `LLMOS.ModelUpdated` | 001-Model-Registry.md | Model health/metrics updated |
| 554 | `LLMOS.ProviderRegistered` | 013-Provider-SDK.md | Provider initialized |
| 555 | `LLMOS.ProviderDeregistered` | 013-Provider-SDK.md | Provider shut down |
| 556 | `LLMOS.ProviderHealthChanged` | 001-Model-Registry.md | Provider health transitioned |
| 557 | `LLMOS.CostOptimized` | 007-Cost-Optimizer.md | Cost estimation and optimization complete |
| 558 | `LLMOS.CacheHit` | 011-Cache.md | Cache lookup hit |
| 559 | `LLMOS.CacheMiss` | 011-Cache.md | Cache lookup miss |
| 560 | `LLMOS.CacheStored` | 011-Cache.md | Response cached |
| 561 | `LLMOS.CacheEvicted` | 011-Cache.md | Cache entry evicted |
| 562 | `LLMOS.ContextBuilt` | 004-Context-Builder.md | Context window assembled |
| 563 | `LLMOS.MemoryInjected` | 005-Memory-Injection.md | Memories injected into context |
| 564 | `LLMOS.PromptCompiled` | 003-Prompt-Compiler.md | Prompt compiled from template |
| 565 | `LLMOS.GuardrailChecked` | 010-Guardrails.md | Guardrail evaluation (input or output) |

#### LLMOS Pipeline Events (Execution)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 566 | `LLMOS.ProviderCalled` | 009-Retry-Engine.md | Provider API call made |
| 567 | `LLMOS.ProviderRetry` | 009-Retry-Engine.md | Retry triggered on provider error |
| 568 | `LLMOS.CircuitBreakerOpened` | 009-Retry-Engine.md | Circuit breaker opened for model |
| 569 | `LLMOS.CircuitBreakerClosed` | 009-Retry-Engine.md | Circuit breaker closed for model |
| 570 | `LLMOS.StreamChunk` | 008-Streaming-Manager.md | Stream chunk emitted |
| 571 | `LLMOS.StreamCompleted` | 008-Streaming-Manager.md | Stream terminated |
| 572 | `LLMOS.StreamError` | 008-Streaming-Manager.md | Mid-stream error occurred |

#### LLMOS Pipeline Events (Post-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 573 | `LLMOS.ResponseValidated` | 012-Response-Validator.md | Response passed validation |
| 574 | `LLMOS.ResponseValidationFailed` | 012-Response-Validator.md | Response failed validation |
| 575 | `LLMOS.ResponseValidationRetry` | 012-Response-Validator.md | Validation retry triggered |

#### LLMOS Model Provider Interfaces (SDK)

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 576 | Interface | `ModelProvider` | 013-Provider-SDK.md | Interface for AI model providers |
| 577 | Method | `initialize(config)` | 013-Provider-SDK.md | Initialize provider with config |
| 578 | Method | `healthCheck()` | 013-Provider-SDK.md | Report provider health |
| 579 | Method | `shutdown()` | 013-Provider-SDK.md | Graceful shutdown |
| 580 | Method | `listModels()` | 013-Provider-SDK.md | List available models |
| 581 | Method | `execute(request)` | 013-Provider-SDK.md | Execute model inference |
| 582 | Method | `executeStream(request)` | 013-Provider-SDK.md | Execute streaming inference |
| 583 | Method | `embed(inputs, model)` | 013-Provider-SDK.md | Generate embeddings |
| 584 | Method | `countTokens(content, model)` | 013-Provider-SDK.md | Count tokens for content |

#### LLMOS Schemas

| # | Schema | Source | Description |
|---|--------|--------|-------------|
| 585 | `InferenceRequest` | 000-Overview.md | Full LLMOS request envelope |
| 586 | `InferenceResponse` | 000-Overview.md | Full LLMOS response envelope |
| 587 | `LLMOSChunk` | 008-Streaming-Manager.md | Streaming chunk schema |
| 588 | `ModelRequirements` | 000-Overview.md | Model selection constraints |
| 589 | `MemoryConfig` | 000-Overview.md | Memory retrieval configuration |
| 590 | `CachePolicy` | 011-Cache.md | Cache read/write behavior |
| 591 | `ModelEntry` | 001-Model-Registry.md | Registered model record |
| 592 | `CompiledPrompt` | 003-Prompt-Compiler.md | Compiled prompt structure |
| 593 | `ContextPayload` | 004-Context-Builder.md | Context window payload |
| 594 | `RetryConfig` | 009-Retry-Engine.md | Retry and fallback configuration |
| 595 | `GuardrailRule` | 010-Guardrails.md | Guardrail rule definition |
| 596 | `ProviderRequest` | 013-Provider-SDK.md | Provider-level request format |
| 597 | `ProviderResponse` | 013-Provider-SDK.md | Provider-level response format |
| 598 | `ProviderError` | 013-Provider-SDK.md | Provider error structure |
| 599 | `EntityTokenBudget` | 006-Token-Budget-Manager.md | Entity token budget structure |
| 600 | `CostEstimate` | 007-Cost-Optimizer.md | Cost estimation structure |
| 601 | `PromptTemplate` | 003-Prompt-Compiler.md | Prompt template definition |

---

## 7. Domains

### 8.1 Trading

**Source:** `Bible/07-Domains/Trading/000-Overview.md`

| # | Event | Description |
|---|-------|-------------|
| 477 | `Trading.StrategyResearched` | Strategy research completes |
| 478 | `Trading.BacktestRun` | Backtest execution finishes |
| 479 | `Trading.PaperTradeCompleted` | Paper trading phase finishes |
| 480 | `Trading.StrategyDeployed` | Strategy is deployed to live trading |
| 481 | `Trading.OrderPlaced` | Order is submitted to exchange |
| 482 | `Trading.OrderFilled` | Order execution confirmed |
| 483 | `Trading.OrderRejected` | Order is rejected by exchange or risk |
| 484 | `Trading.RiskLimitBreached` | A risk limit is approached or breached |
| 485 | `Trading.StrategyRetired` | Strategy is decommissioned |

---

### 8.2 Security Domain

**Source:** `Bible/07-Domains/Security/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 486 | Capability | `monitor_endpoints` | Security domain worker capability — monitor endpoints |
| 487 | Capability | `analyze_network` | Security domain worker capability — analyze network traffic |
| 488 | Capability | `detect_intrusion` | Security domain worker capability — detect intrusion |
| 489 | Capability | `alert_triage` | Security domain worker capability — triage alerts |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 490 | `Security.VulnerabilityFound` | Potential vulnerability identified |
| 491 | `Security.VulnerabilityVerified` | Vulnerability confirmed in sandbox |
| 492 | `Security.ExploitAttempted` | Exploit verification executed |
| 493 | `Security.IncidentDetected` | Security incident is identified |
| 494 | `Security.IncidentContained` | Incident containment completed |
| 495 | `Security.IncidentResolved` | Incident fully resolved |
| 496 | `Security.IntelReportGenerated` | Threat intelligence report produced |
| 497 | `Security.ComplianceAuditRun` | Compliance audit completes |

---

## 8. Federation

### 8.1 AIP — Agent Interoperability Protocol

**Source:** `Bible/06-Services/Federation/001-AIP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 498 | `connectToRemoteAgent(remote_session_id, instance_id)` | mTLS + identity | Initiate cross-instance session |
| 499 | `sendAgentMessage(session_id, message)` | mTLS + identity | Send message to remote session |
| 500 | `disconnectAgent(session_id)` | mTLS | Terminate cross-instance session |
| 501 | `getAgentStatus(session_id)` | mTLS | Check remote session status |

#### AIP Events

| # | Event | Description |
|---|-------|-------------|
| 502 | `AIP.AgentConnected` | Remote session connected |
| 503 | `AIP.AgentDisconnected` | Remote session disconnected |
| 504 | `AIP.MessageSent` | Message transmitted |
| 505 | `AIP.MessageReceived` | Message received |
| 506 | `AIP.ConnectionFailed` | Connection attempt failed |

---

### 8.2 SXP — Security Exchange Protocol

**Source:** `Bible/06-Services/Federation/007-SXP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 507 | `shareThreat(threat_data, severity)` | mTLS + signature | Share threat intelligence |
| 508 | `subscribeThreats(filter, callback_endpoint)` | mTLS | Subscribe to threat feed |
| 509 | `acknowledgeThreat(threat_id, action_taken)` | mTLS | Acknowledge receipt of threat |
| 510 | `escalateThreat(threat_id, escalation_reason)` | Security Council | Request coordinated response |
| 511 | `getThreatStatus(threat_id)` | mTLS | Query threat resolution status |

#### SXP Events

| # | Event | Description |
|---|-------|-------------|
| 512 | `SXP.ThreatShared` | Threat intelligence shared |
| 513 | `SXP.ThreatAcknowledged` | Receipt acknowledged |
| 514 | `SXP.ThreatEscalated` | Threat escalated |
| 515 | `SXP.ThreatResolved` | Threat resolved |
| 516 | `SXP.SubscriptionCreated` | Threat feed subscription |

---

## 9. Governance

| # | Type | Source | Description |
|---|------|--------|-------------|
| 517 | Event | `Bible/01-Governance/001-CLS.md` | CLS constitutional amendment lifecycle events |
| 518 | Event | `Bible/01-Governance/002-DGP.md` | DGP decision assessed events |
| 519 | Event | `Bible/01-Governance/003-CRP.md` | CRP constitutional review proposal events |
| 520 | RPC (ACF) | `Bible/01-Governance/004-CKR.md` | CKR constitutional knowledge registry query interface |
| 521 | Event | `Bible/01-Governance/004-CKR.md` | CKR knowledge registry lifecycle events |
| 522 | Event | `Bible/01-Governance/005-ADG.md` | ADG architecture decision events |
| 523 | Event | `Bible/01-Governance/006-AKM.md` | AKM knowledge management lifecycle events |

---

## 10. Cross-Cutting

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 524 | Interface | `AuthMethod` | `Bible/00-Foundations/002-Design-DNA.md` | Interface for implementing new authentication methods |
| 525 | Event | `Lifecycle.StateChanged` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity state transitioned |
| 526 | Event | `Lifecycle.TransitionDenied` | `Bible/00-Foundations/008-Object-Lifecycle.md` | State transition denied |
| 527 | Event | `Lifecycle.EntityCreated` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity created |
| 528 | Event | `Lifecycle.EntityCompleted` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity lifecycle completed |
| 529 | Event | `Lifecycle.EntityArchived` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity archived |
| 530 | Schema | Canonical API Envelope | `Bible/08-Interfaces/API/000-Specifications.md` | Standard envelope: api_version, message_id, correlation_id, timestamp, source_entity_id, target_entity_id, auth_token, payload |
| 531 | Schema | Error Response Schema | `Bible/08-Interfaces/API/000-Specifications.md` | Standard error: code, message, details, correlation_id |

#### Framework API Events

| # | Event | Description |
|---|-------|-------------|
| 532 | `API.ContractPublished` | New API contract registered |
| 533 | `API.ContractDeprecated` | API version deprecated |
| 534 | `API.RequestProcessed` | API request completes |
| 535 | `API.RateLimitExceeded` | Rate limit exceeded |
| 536 | `API.SchemaValidationFailed` | Schema validation failed |

---

## 11. Appendix: Schema Index

Key schemas referenced by API entries:

| # | Schema | Defined In | Description |
|---|--------|------------|-------------|
| S1 | `Envelope` | `Bible/06-Services/ACF/002-Messages.md:28` | Message routing and metadata |
| S2 | `Message` | `Bible/06-Services/ACF/002-Messages.md:22` | Fundamental communication unit |
| S3 | `WorkerMessage` | `Bible/03-Institutions/Workers/004-WCS.md:142` | Worker-to-worker message |
| S4 | `ExecutionContext` | `Bible/04-Execution/Runtime/001-SDK.md:71` | Execution request context |
| S5 | `ExecutionResult` | `Bible/04-Execution/Runtime/001-SDK.md:85` | Execution output |
| S6 | `ExecutionChunk` | `Bible/04-Execution/Runtime/001-SDK.md:102` | Streaming execution chunk |
| S7 | `RetryPolicy` | `Bible/06-Services/ACF/006-Reliability.md:79` | Retry configuration |
| S8 | `DeadLetterMessage` | `Bible/06-Services/ACF/006-Reliability.md:97` | Undeliverable message |
| S9 | `DeliveryStatus` | `Bible/06-Services/ACF/002-Messages.md:142` | Delivery tracking |
| S10 | `Canonical API Envelope` | `Bible/08-Interfaces/API/000-Specifications.md:41` | Standard API envelope |

---

## Legend

- **RPC (ACF):** Method called over ACF request/response pattern
- **REST:** HTTP endpoint exposed through API gateway
- **Stream:** Long-lived streaming channel (ACF stream or WebSocket)
- **Pub-Sub (ACF):** Publish/subscribe over ACF topics
- **Interface:** Abstract trait/interface that concrete implementations must satisfy
- **Event:** Domain event emitted to ACF event stream for observation
- **Message:** Structured data type sent as payload
- **Schema:** Data structure/contract definition
- **Capability:** Named capability that workers/entities may possess
