# AIOS Master API Specification

> **Purpose:** Single-source-of-truth registry for every concrete API endpoint, ACF topic, RPC method, streaming channel, interface method, and event type across the entire AIOS platform.
> **Framework Spec:** `Bible/08-Interfaces/API/000-Specifications.md` (API design conventions, versioning, error schemas)
> **Status:** Registry â€” catalogs what exists; does not prescribe design.

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

### 1.1 PSAP â€” Platform Service Access Point

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

### 1.2 EVS â€” Event Store

**Source:** `Bible/05-Platform/004-EVS.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `appendEvent(stream_id, event_type, data, metadata)` | ACF token | Append event to stream |
| 2 | `readStream(stream_id, from_version?, to_version?)` | ACF token | Read events from stream |
| 3 | `readStreamByTime(stream_id, from_time, to_time)` | ACF token | Read events by time range |
| 4 | `readEvent(event_id)` | ACF token | Read specific event by ID |
| 5 | `readEventByVersion(stream_id, version)` | ACF token | Read specific event version |
| 6 | `subscribeStream(stream_id, subscriber)` | ACF token | Subscribe to event stream |
| 7 | `queryEvents(query)` | ACF token | Query events by filter |
| 8 | `queryEventsByType(event_type, from_time, to_time)` | ACF token | Query events by type and time range |
| 9 | `getEventCount(stream_id)` | ACF token | Get event count |
| 10 | `getStreamInfo(stream_id)` | ACF token | Get stream info |
| 11 | `listStreams(filter?)` | ACF token | List all streams |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 12 | `EVS.EventAppended` | Event written to stream |
| 13 | `EVS.StreamCreated` | Event stream initialized |
| 14 | `EVS.SnapshotCreated` | Snapshot taken |
| 15 | `EVS.SubscriptionActivated` | Subscriber subscribed to stream |
| 16 | `EVS.SubscriptionEnded` | Subscriber unsubscribed |
| 17 | `EVS.ReadReplicaAdded` | Read replica came online |
| 18 | `EVS.RaftLeaderElected` | New Raft leader elected |
| 19 | `EVS.RetentionTriggered` | Events moved to cold storage |

---

### 1.3 EPG â€” Event Processing Graph

**Source:** `Bible/05-Platform/006-EPG.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Stream | Event Processing Graph (EPG) | ACF-level | DAG-based event stream processing (filter, transform, enrich, aggregate, route) |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 2 | `EPG.GraphDefined` | New processing graph defined |
| 3 | `EPG.GraphActivated` | Graph begins processing |
| 4 | `EPG.GraphDeactivated` | Graph stops processing |
| 5 | `EPG.GraphUpdated` | Graph definition modified |
| 6 | `EPG.NodeProcessed` | Graph node completed processing |
| 7 | `EPG.NodeFailed` | Node fails processing |
| 8 | `EPG.EventDeadLettered` | Event exceeds retry limit |
| 9 | `EPG.EnrichmentCacheHit` | Enrichment served from cache |
| 10 | `EPG.EnrichmentCacheMiss` | Enrichment fetched from source |

---

### 1.4 EIP â€” External Integration Protocol

**Source:** `Bible/05-Platform/007-EIP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `Connector` | N/A | All EIP connectors implement this interface |
| 2 | REST/gRPC/AMQP/MQTT | External Integration Protocol | mTLS (varies) | Protocol for webhook, Kafka, MQTT, AMQP, REST, gRPC connectors |

#### Messages

| # | Message | Description |
|---|---------|-------------|
| 3 | `ConnectorConfig` | Protocol, endpoint, format, authentication config |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 4 | `EIP.ConnectorCreated` | Connector defined |
| 5 | `EIP.ConnectorActivated` | Connector starts processing |
| 6 | `EIP.ConnectorDeactivated` | Connector stops |
| 7 | `EIP.ConnectorFailed` | Connector error |
| 8 | `EIP.ConnectorReconnected` | Connector re-establishes connection |
| 9 | `EIP.ConnectorArchived` | Connector decommissioned |
| 10 | `EIP.EventExported` | Event sent to external system |
| 11 | `EIP.EventImported` | Event received from external system |
| 12 | `EIP.SecurityViolation` | Security rule violated |
| 13 | `EIP.CircuitBreakerTripped` | Circuit breaker opens |

---

### 1.5 CP â€” Credential Provider

**Source:** `Bible/05-Platform/012-CP.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 1 | Interface | `Credential` | All credential types implement this |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 2 | `CP.CredentialRequested` | Credential is requested |
| 3 | `CP.CredentialApproved` | Request is approved |
| 4 | `CP.CredentialIssued` | Credential is generated |
| 5 | `CP.CredentialActivated` | Credential becomes active |
| 6 | `CP.CredentialRotated` | Credential is rotated |
| 7 | `CP.CredentialRevoked` | Credential is revoked |
| 8 | `CP.CredentialExpired` | Credential expires |
| 9 | `CP.RotationScheduled` | Rotation is scheduled |
| 10 | `CP.ValidationFailed` | Credential fails validation |

---

### 1.6 Graph Framework

**Source:** `Bible/05-Platform/013-Graph-Framework.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `GraphStore` | N/A | All graph storage backends implement this |
| 2 | RPC (ACF) | Graph Framework operations | ACF-level | Graph queries via ACF |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 3 | `GF.GraphCreated` | New graph created |
| 4 | `GF.GraphDeleted` | Graph removed |
| 5 | `GF.GraphCleared` | Graph content cleared |
| 6 | `GF.NodeAdded` | Node added to graph |
| 7 | `GF.NodeRemoved` | Node removed |
| 8 | `GF.EdgeAdded` | Edge added |
| 9 | `GF.EdgeRemoved` | Edge removed |
| 10 | `GF.QueryExecuted` | Query run |
| 11 | `GF.AnalysisCompleted` | Analysis operation done |

---

### 1.7 LMS â€” Lifecycle Management Service

**Source:** `Bible/05-Platform/000-LMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | RPC (ACF) | LMS transition requests | ACF token | Entity lifecycle state transitions via ACF |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 2 | `LMS.EntityCreated` | Entity created |
| 3 | `LMS.StateChanged` | Entity state transitioned |
| 4 | `LMS.TransitionDenied` | State transition denied |
| 5 | `LMS.EntityCompleted` | Entity lifecycle completed |
| 6 | `LMS.EntityArchived` | Entity archived |
| 7 | `LMS.CascadeTriggered` | Parent triggers child cascade |
| 8 | `LMS.SnapshotCreated` | Snapshot persisted |

---

## 2. Core Engines

### 2.1 Academy â€” Knowledge Management

**Source:** `Bible/02-Core/Academy/016-Knowledge-API.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `academy.knowledge.create` | `knowledge.propose` | Propose a new knowledge artifact |
| 2 | `academy.knowledge.validate` | `knowledge.validate` | Trigger validation of knowledge artifact |
| 3 | `academy.knowledge.accept` | `knowledge.accept` | Accept validated knowledge into Registry |
| 4 | `academy.knowledge.query` | `knowledge.query` | Query knowledge artifacts by graph traversal |
| 5 | `academy.knowledge.search` | `knowledge.query` | Full-text, semantic, or faceted search |
| 6 | `academy.knowledge.get` | `knowledge.query` | Retrieve specific knowledge artifact by ID |
| 7 | `academy.knowledge.provenance` | `knowledge.query` | Get full provenance chain for artifact |
| 8 | `academy.knowledge.list` | `knowledge.query` | List knowledge artifacts with filters |
| 9 | `academy.knowledge.deprecate` | `knowledge.deprecate` | Deprecate a knowledge artifact |
| 10 | `academy.knowledge.compose` | `knowledge.compose.{method}` | Request KCE knowledge composition |
| 11 | `academy.knowledge.execute` | `knowledge.execute.{type}` | Request KEE knowledge execution |

#### Pub-Sub (ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 12 | `academy.knowledge.subscribe` | `knowledge.subscribe` | Subscribe to knowledge lifecycle events |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 13 | `API.RequestReceived` | API received a request |
| 14 | `API.RequestCompleted` | API completed processing |
| 15 | `API.RequestFailed` | API encountered an error |
| 16 | `API.RateLimitExceeded` | Rate limit exceeded |
| 17 | `API.SubscriptionCreated` | Subscription created |
| 18 | `API.SubscriptionRemoved` | Subscription removed |

---

### 2.2 Academy â€” Knowledge Search (REST Gateway)

**Source:** `Bible/02-Core/Academy/010-Knowledge-Search.md`

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 1 | `GET /search?q=...&fields=...&operator=...` | JWT | Full-text knowledge search |
| 2 | `GET /search?q=...&type=semantic&top_k=...` | JWT | Semantic knowledge search |
| 3 | `GET /search?type=graph&start_node_id=...&edge_types=...&max_depth=...` | JWT | Graph-based knowledge search |
| 4 | `GET /search?type=operational&organization_id=...&tags=...&confidence_min=...` | JWT | Faceted/operational knowledge search |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 5 | `Search.QueryExecuted` | Search query is executed |
| 6 | `Search.ResultClicked` | Consumer selects a search result |
| 7 | `Search.IndexUpdated` | Search index is updated |
| 8 | `Search.IndexRebuilt` | Full index rebuild completes |
| 9 | `Search.RankingRecalculated` | Ranking weights are updated |

---

### 2.3 Academy â€” KMS Query Interface

**Source:** `Bible/02-Core/Academy/002-KMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | RPC (ACF) | KMS query interface | ACF-level | Knowledge management storage and retrieval queries |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 2 | `KMS.ArtifactCreated` | New knowledge artifact created |
| 3 | `KMS.ArtifactUpdated` | Existing artifact updated |
| 4 | `KMS.ArtifactDeprecated` | Artifact deprecated |
| 5 | `KMS.ArtifactArchived` | Artifact archived |
| 6 | `KMS.SnapshotCreated` | Snapshot written for version chain |
| 7 | `KMS.QueryExecuted` | Query executed against KMS |

---

### 2.4 Academy â€” Knowledge SDK Provider Interface

**Source:** `Bible/02-Core/Academy/015-Knowledge-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `authenticate(entity_id, credentials)` | ACF token | Authenticate with ATS and obtain session token |
| 2 | `setIdentity(identity)` | ACF token | Set identity for subsequent operations |
| 3 | `getCurrentEntity()` | ACF token | Returns authenticated entity info |
| 4 | `hasCapability(capability)` | ACF token | Check if entity has a specific capability |
| 5 | `search(query, options)` | ACF token | Full-text and semantic search |
| 6 | `getKnowledge(id)` | ACF token | Retrieve artifact by ID |
| 7 | `listKnowledge(filters)` | ACF token | List artifacts matching filters |
| 8 | `getProvenance(id, options)` | ACF token | Get provenance chain |
| 9 | `queryGraph(query)` | ACF token | Graph traversal query |
| 10 | `subscribe(topic, callback)` | ACF token | Subscribe to knowledge events |
| 11 | `unsubscribe(subscriptionId)` | ACF token | Unsubscribe from events |
| 12 | `onKnowledgeAccepted(callback)` | ACF token | Convenience subscription for accepted events |
| 13 | `onKnowledgeDeprecated(callback)` | ACF token | Convenience subscription for deprecation events |
| 14 | `proposeKnowledge(artifact)` | ACF token | Submit knowledge for validation |
| 15 | `getProposalStatus(proposalId)` | ACF token | Check proposal status |
| 16 | `withdrawProposal(proposalId)` | ACF token | Withdraw a pending proposal |
| 17 | `resubmitKnowledge(proposalId, updatedArtifact)` | ACF token | Resubmit with revisions |
| 18 | `composeUnion(artifactIds)` | ACF token | Union composition |
| 19 | `composeIntersection(artifactIds)` | ACF token | Intersection composition |
| 20 | `composeAnalogy(sourceId, targetDomain)` | ACF token | Analogy composition |
| 21 | `composeInduction(artifactIds)` | ACF token | Induction composition |
| 22 | `composeDeduction(principleId, context)` | ACF token | Deduction composition |
| 23 | `getCompositionStatus(requestId)` | ACF token | Check composition request status |
| 24 | `executeKnowledge(knowledgeId, context)` | ACF token | Execute a knowledge artifact |
| 25 | `getExecutionStatus(executionId)` | ACF token | Check execution status |
| 26 | `cancelExecution(executionId)` | ACF token | Cancel a pending execution |
| 27 | `getExecutionResult(executionId)` | ACF token | Get execution result |

#### SDK Events

| # | Event | Description |
|---|-------|-------------|
| 28 | `SDK.Authenticated` | SDK successfully authenticates |
| 29 | `SDK.QueryExecuted` | SDK executes a query |
| 30 | `SDK.KnowledgeProposed` | SDK proposes knowledge |
| 31 | `SDK.EventSubscribed` | SDK subscribes to a topic |
| 32 | `SDK.EventReceived` | SDK receives an event |
| 33 | `SDK.ErrorEncountered` | SDK encounters an error |

---

## 3. Brain

### 3.1 Sou â€” Executive Intelligence

**Source:** `Bible/02-Core/Brain/Sou/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 1 | Interface | `SouIdentity` | Sou's persistent identity â€” name, purpose, history |
| 2 | Interface | `SouPersonality` | Sou's behavioral traits, values, communication style |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 3 | `Sou.InputReceived` | Input entered Sou's processing |
| 4 | `Sou.DecisionMade` | Sou made a strategic decision |
| 5 | `Sou.MissionCreated` | Sou created a mission |
| 6 | `Sou.ResponseSent` | Sou sent a user-facing response |

---

### 3.2 LLMOS â€” AI Inference Pipeline

**Source:** `Bible/02-Core/Brain/LLMOS/`

#### RPC Methods (via ACF â€” `acf://llmos/inference`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `inference(request)` | Execution token | Full pipeline inference â€” non-streaming |
| 2 | `inferenceStream(request)` | Execution token | Full pipeline inference â€” streaming |
| 3 | `embed(inputs, model)` | Execution token | Generate embeddings |
| 4 | `countTokens(content, model)` | Execution token | Count tokens for content on specific model |
| 5 | `getModelStatus()` | ACF-level | Get status of all registered models |

#### Pipeline Events (Gateway)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 6 | `LLMOS.RequestReceived` | 000-Overview.md | Request entered pipeline |
| 7 | `LLMOS.SecurityChecked` | 000-Overview.md | Security Council verification passed |
| 8 | `LLMOS.RateChecked` | 000-Overview.md | Rate limit check passed |
| 9 | `LLMOS.BudgetChecked` | 006-Token-Budget-Manager.md | Token budget verified |
| 10 | `LLMOS.BudgetReconciled` | 006-Token-Budget-Manager.md | Budget reconciled after request |
| 11 | `LLMOS.RequestCompleted` | 000-Overview.md | Pipeline completed successfully |
| 12 | `LLMOS.RequestFailed` | 000-Overview.md | Pipeline failed |

#### Pipeline Events (Pre-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 13 | `LLMOS.ModelsResolved` | 001-Model-Registry.md | Model candidates matched requirements |
| 14 | `LLMOS.ModelSelected` | 002-Router.md | Router selected optimal model |
| 15 | `LLMOS.ModelRegistered` | 001-Model-Registry.md | New model registered |
| 16 | `LLMOS.ModelDeregistered` | 001-Model-Registry.md | Model deregistered |
| 17 | `LLMOS.ModelUpdated` | 001-Model-Registry.md | Model health/metrics updated |
| 18 | `LLMOS.ProviderRegistered` | 013-Provider-SDK.md | Provider initialized |
| 19 | `LLMOS.ProviderDeregistered` | 013-Provider-SDK.md | Provider shut down |
| 20 | `LLMOS.ProviderHealthChanged` | 001-Model-Registry.md | Provider health transitioned |
| 21 | `LLMOS.CostOptimized` | 007-Cost-Optimizer.md | Cost estimation and optimization complete |
| 22 | `LLMOS.CacheHit` | 011-Cache.md | Cache lookup hit |
| 23 | `LLMOS.CacheMiss` | 011-Cache.md | Cache lookup miss |
| 24 | `LLMOS.CacheStored` | 011-Cache.md | Response cached |
| 25 | `LLMOS.CacheEvicted` | 011-Cache.md | Cache entry evicted |
| 26 | `LLMOS.ContextBuilt` | 004-Context-Builder.md | Context window assembled |
| 27 | `LLMOS.MemoryInjected` | 005-Memory-Injection.md | Memories injected into context |
| 28 | `LLMOS.PromptCompiled` | 003-Prompt-Compiler.md | Prompt compiled from template |
| 29 | `LLMOS.GuardrailChecked` | 010-Guardrails.md | Guardrail evaluation (input or output) |

#### Pipeline Events (Execution)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 30 | `LLMOS.ProviderCalled` | 009-Retry-Engine.md | Provider API call made |
| 31 | `LLMOS.ProviderRetry` | 009-Retry-Engine.md | Retry triggered on provider error |
| 32 | `LLMOS.CircuitBreakerOpened` | 009-Retry-Engine.md | Circuit breaker opened for model |
| 33 | `LLMOS.CircuitBreakerClosed` | 009-Retry-Engine.md | Circuit breaker closed for model |
| 34 | `LLMOS.StreamChunk` | 008-Streaming-Manager.md | Stream chunk emitted |
| 35 | `LLMOS.StreamCompleted` | 008-Streaming-Manager.md | Stream terminated |
| 36 | `LLMOS.StreamError` | 008-Streaming-Manager.md | Mid-stream error occurred |

#### Pipeline Events (Post-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 37 | `LLMOS.ResponseValidated` | 012-Response-Validator.md | Response passed validation |
| 38 | `LLMOS.ResponseValidationFailed` | 012-Response-Validator.md | Response failed validation |
| 39 | `LLMOS.ResponseValidationRetry` | 012-Response-Validator.md | Validation retry triggered |

#### Model Provider Interfaces (SDK)

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 40 | Interface | `ModelProvider` | 013-Provider-SDK.md | Interface for AI model providers |
| 41 | Method | `initialize(config)` | 013-Provider-SDK.md | Initialize provider with config |
| 42 | Method | `healthCheck()` | 013-Provider-SDK.md | Report provider health |
| 43 | Method | `shutdown()` | 013-Provider-SDK.md | Graceful shutdown |
| 44 | Method | `listModels()` | 013-Provider-SDK.md | List available models |
| 45 | Method | `execute(request)` | 013-Provider-SDK.md | Execute model inference |
| 46 | Method | `executeStream(request)` | 013-Provider-SDK.md | Execute streaming inference |
| 47 | Method | `embed(inputs, model)` | 013-Provider-SDK.md | Generate embeddings |
| 48 | Method | `countTokens(content, model)` | 013-Provider-SDK.md | Count tokens for content |

#### Schemas

| # | Schema | Source | Description |
|---|--------|--------|-------------|
| 49 | `InferenceRequest` | 000-Overview.md | Full LLMOS request envelope |
| 50 | `InferenceResponse` | 000-Overview.md | Full LLMOS response envelope |
| 51 | `LLMOSChunk` | 008-Streaming-Manager.md | Streaming chunk schema |
| 52 | `ModelRequirements` | 000-Overview.md | Model selection constraints |
| 53 | `MemoryConfig` | 000-Overview.md | Memory retrieval configuration |
| 54 | `CachePolicy` | 011-Cache.md | Cache read/write behavior |
| 55 | `ModelEntry` | 001-Model-Registry.md | Registered model record |
| 56 | `CompiledPrompt` | 003-Prompt-Compiler.md | Compiled prompt structure |
| 57 | `ContextPayload` | 004-Context-Builder.md | Context window payload |
| 58 | `RetryConfig` | 009-Retry-Engine.md | Retry and fallback configuration |
| 59 | `GuardrailRule` | 010-Guardrails.md | Guardrail rule definition |
| 60 | `ProviderRequest` | 013-Provider-SDK.md | Provider-level request format |
| 61 | `ProviderResponse` | 013-Provider-SDK.md | Provider-level response format |
| 62 | `ProviderError` | 013-Provider-SDK.md | Provider error structure |
| 63 | `EntityTokenBudget` | 006-Token-Budget-Manager.md | Entity token budget structure |
| 64 | `CostEstimate` | 007-Cost-Optimizer.md | Cost estimation structure |
| 65 | `PromptTemplate` | 003-Prompt-Compiler.md | Prompt template definition |

---

### 3.3 DTS â€” Decision & Trust Scoring

**Source:** `Bible/02-Core/DTS/001-Architecture.md`, `Bible/02-Core/DTS/003-Sim-Engines.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 1 | Interface | `DecisionEvaluator` | Interface for evaluating decisions |
| 2 | Interface | `EvaluationResult` | Interface for evaluation results |
| 3 | Interface | `TrustScorer` | Interface for trust scoring |
| 4 | Interface | `TrustScore` | Interface for trust score data |
| 5 | Interface | `SimEngine` | All simulation engines implement this |

---

### 3.4 ROS â€” Resource Orchestration

**Source:** `Bible/02-Core/ROS/008-Provider-SDK.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 1 | Interface | `ResourceProvider` | SDK interface that all resource providers must implement |

---

## 4. Security Council

The Security Council is the constitutional authority for all security operations. It operates the 7-stage verification pipeline that gates every action before execution. See `Bible/04-Execution/Security/` for full specifications.

### 4.1 Verification Pipeline (Execution-Auth)

**Source:** `Bible/04-Execution/Security/Execution-Auth/000-EAS.md`

The 7-stage pipeline enforces Law 8 (Verification-First). Every action passes through all stages before receiving an execution token.

| # | Stage | Service | Function |
|---|-------|---------|----------|
| 1 | 1 â€” Identity | IDS | Verify actor identity exists and is active |
| 2 | 2 â€” Authentication | ATS | Verify authentication token is valid |
| 3 | 3 â€” Authorization | AZS | Verify actor is authorized for this action |
| 4 | 4 â€” Policy | Policy System | Verify action complies with active policies |
| 5 | 5 â€” Capability | CCA | Verify actor has required capabilities |
| 6 | 6 â€” Risk | Risk Engine | Evaluate risk level; escalate if above threshold |
| 7 | 7 â€” Execution Auth | Execution-Auth | Issue execution token; reserve resources via ROS |

#### Pipeline Events

| # | Event | Description |
|---|-------|-------------|
| 8 | `SC.PipelineStarted` | Action entered verification pipeline |
| 9 | `SC.StagePassed` | Individual pipeline stage passed |
| 10 | `SC.StageFailed` | Individual pipeline stage failed |
| 11 | `SC.PipelineCompleted` | All 7 stages passed, execution token issued |
| 12 | `SC.PipelineDenied` | Action denied at a pipeline stage |
| 13 | `SC.ExecutionTokenIssued` | Execution authorization token created |
| 14 | `SC.ExecutionTokenRevoked` | Execution token revoked before use |

---

### 4.2 IDS â€” Identity Service

**Source:** `Bible/04-Execution/Security/IDS/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `IdentityFactory` | Security Council | Create new identities |
| 2 | Interface | `IdentityRegistry` | Security Council | Register, resolve, and manage identity records |
| 3 | RPC | `createIdentity(entity_type, attributes)` | Security Council | Create a new constitutional identity |
| 4 | RPC | `resolveIdentity(entity_id)` | ACF-level | Resolve identity to its current attributes |
| 5 | RPC | `validateIdentity(entity_id)` | ACF-level | Verify identity is active and valid |
| 6 | RPC | `deprecateIdentity(entity_id, reason)` | Security Council | Deprecate an identity |

#### IDS Events

| # | Event | Description |
|---|-------|-------------|
| 7 | `IDS.IdentityCreated` | New identity registered |
| 8 | `IDS.IdentityResolved` | Identity resolution completed |
| 9 | `IDS.IdentityDeprecated` | Identity deprecated |
| 10 | `IDS.IdentitySuspended` | Identity temporarily suspended |

---

### 4.3 ATS â€” Authentication Token Service

**Source:** `Bible/04-Execution/Security/ATS/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `AuthProvider` | Security Council | All authentication methods implement this |
| 2 | RPC | `authenticate(entity_id, credentials)` | None (pre-auth) | Authenticate entity; return session token |
| 3 | RPC | `validateToken(token)` | ACF-level | Validate existing authentication token |
| 4 | RPC | `revokeToken(token)` | Security Council | Revoke an authentication token |
| 5 | RPC | `requestMFA(entity_id, method)` | ACF-level | Request multi-factor authentication |
| 6 | RPC | `verifyMFA(entity_id, challenge_response)` | ACF-level | Verify MFA challenge response |

#### ATS Events

| # | Event | Description |
|---|-------|-------------|
| 7 | `ATS.Authenticated` | Entity authenticated successfully |
| 8 | `ATS.AuthenticationFailed` | Authentication attempt failed |
| 9 | `ATS.MFARequired` | MFA challenge issued |
| 10 | `ATS.MFAVerified` | MFA challenge passed |
| 11 | `ATS.TokenIssued` | Authentication token issued |
| 12 | `ATS.TokenRevoked` | Token revoked |
| 13 | `ATS.TokenExpired` | Token expired naturally |

---

### 4.4 AZS â€” Authorization Service

**Source:** `Bible/04-Execution/Security/AZS/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `AuthorizationProvider` | Security Council | All authorization methods implement this |
| 2 | RPC | `checkPermission(entity_id, action, resource)` | Pipeline | Check RBAC permission |
| 3 | RPC | `checkABAC(entity_id, action, resource, context)` | Pipeline | Check attribute-based access control |
| 4 | RPC | `checkCapability(entity_id, capability_id)` | Pipeline | Check capability-based authorization |
| 5 | RPC | `assignRole(entity_id, role)` | Security Council | Assign a role to an entity |
| 6 | RPC | `revokeRole(entity_id, role)` | Security Council | Revoke a role from an entity |

#### AZS Events

| # | Event | Description |
|---|-------|-------------|
| 7 | `AZS.Authorized` | Authorization check passed |
| 8 | `AZS.Denied` | Authorization check denied |
| 9 | `AZS.RoleAssigned` | Role assigned to entity |
| 10 | `AZS.RoleRevoked` | Role revoked from entity |

---

### 4.5 Policy System

**Source:** `Bible/04-Execution/Security/Policy-System/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `PolicyEngine` | Security Council | Policy definition and evaluation engine |
| 2 | RPC | `createPolicy(policy_def)` | Security Council | Create a new policy |
| 3 | RPC | `evaluatePolicy(policy_id, context)` | Pipeline | Evaluate action against policy |
| 4 | RPC | `activatePolicy(policy_id)` | Security Council | Activate a policy |
| 5 | RPC | `deactivatePolicy(policy_id)` | Security Council | Deactivate a policy |
| 6 | RPC | `listPolicies(filter?)` | ACF-level | List policies matching filter |

#### Policy Events

| # | Event | Description |
|---|-------|-------------|
| 7 | `POL.PolicyCreated` | New policy defined |
| 8 | `POL.PolicyActivated` | Policy activated |
| 9 | `POL.PolicyDeactivated` | Policy deactivated |
| 10 | `POL.PolicyEvaluated` | Policy evaluation completed |
| 11 | `POL.PolicyViolation` | Action violates a policy |

---

### 4.6 Risk Engine

**Source:** `Bible/04-Execution/Security/Risk/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `RiskScorer` | Security Council | Risk scoring interface |
| 2 | RPC | `evaluateRisk(entity_id, action, context)` | Pipeline | Compute risk score for action |
| 3 | RPC | `getRiskProfile(entity_id)` | Security Council | Get entity's current risk profile |
| 4 | RPC | `escalateRisk(action_id, reason)` | Security Council | Escalate a high-risk action |

#### Risk Events

| # | Event | Description |
|---|-------|-------------|
| 5 | `RSK.RiskScored` | Risk score computed for action |
| 6 | `RSK.ThresholdExceeded` | Risk score exceeded configured threshold |
| 7 | `RSK.RiskEscalated` | Action escalated for manual review |

---

### 4.7 EAS â€” Evidence Audit Service

**Source:** `Bible/04-Execution/Security/Audit/000-EAS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `EvidenceStore` | Security Council | Immutable evidence storage backend |
| 2 | Interface | `EvidenceQuery` | Security Council | Evidence query interface |
| 3 | RPC | `sealEvidence(record)` | Pipeline | Seal an evidence record |
| 4 | RPC | `queryEvidence(query)` | Auditor | Query evidence records |
| 5 | RPC | `exportEvidence(query, format)` | Auditor | Export evidence for external audit |

#### EAS Events

| # | Event | Description |
|---|-------|-------------|
| 6 | `EAS.EvidenceSealed` | New evidence record sealed |
| 7 | `EAS.EvidenceQueried` | Evidence query executed |
| 8 | `EAS.EvidenceExported` | Evidence export completed |

---

### 4.8 CSP â€” Cryptographic Service Provider

**Source:** `Bible/04-Execution/Security/Crypto/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `CryptoProvider` | Security Council | Cryptographic operations interface |
| 2 | RPC | `generateKey(algorithm, purpose)` | Security Council | Generate cryptographic key pair |
| 3 | RPC | `sign(entity_id, payload)` | Security Council | Sign payload with entity key |
| 4 | RPC | `verify(entity_id, payload, signature)` | ACF-level | Verify signature |
| 5 | RPC | `encrypt(payload, recipient_id)` | ACF-level | Encrypt payload for recipient |
| 6 | RPC | `decrypt(ciphertext)` | Security Council | Decrypt ciphertext |
| 7 | RPC | `hash(payload, algorithm)` | ACF-level | Compute cryptographic hash |

#### CSP Events

| # | Event | Description |
|---|-------|-------------|
| 8 | `CSP.KeyGenerated` | New key pair generated |
| 9 | `CSP.KeyRotated` | Key rotated |
| 10 | `CSP.KeyCompromised` | Key reported compromised |
| 11 | `CSP.SignatureVerified` | Signature verification completed |
| 12 | `CSP.EncryptionPerformed` | Encryption operation completed |

---

### 4.9 SSM â€” Session & Secret Management

**Source:** `Bible/04-Execution/Security/SSM/000-SSM.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `SessionManager` | Security Council | Session lifecycle management |
| 2 | Interface | `SecretStore` | Security Council | Encrypted secret storage |
| 3 | RPC | `createSession(entity_id, ttl)` | ACF-level | Create new session |
| 4 | RPC | `validateSession(session_id)` | ACF-level | Validate session is active |
| 5 | RPC | `terminateSession(session_id)` | Security Council | Terminate a session |
| 6 | RPC | `storeSecret(name, value, ttl)` | Security Council | Store an encrypted secret |
| 7 | RPC | `resolveSecret(name)` | Security Council | Resolve a secret (for authorized callers) |
| 8 | RPC | `rotateSecret(name)` | Security Council | Rotate a secret |
| 9 | RPC | `revokeSecret(name)` | Security Council | Revoke a secret |

#### SSM Events

| # | Event | Description |
|---|-------|-------------|
| 10 | `SSM.SessionCreated` | New session created |
| 11 | `SSM.SessionTerminated` | Session terminated |
| 12 | `SSM.SessionExpired` | Session TTL exceeded |
| 13 | `SSM.SecretStored` | Secret encrypted and stored |
| 14 | `SSM.SecretRotated` | Secret rotated |
| 15 | `SSM.SecretRevoked` | Secret revoked |

---

### 4.10 Sandbox â€” Execution Isolation

**Source:** `Bible/04-Execution/Security/Sandbox/000-Isolation.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `SandboxProvider` | Security Council | Execution isolation interface |
| 2 | RPC | `createSandbox(worker_id, resource_limits)` | Pipeline | Create isolated execution environment |
| 3 | RPC | `destroySandbox(sandbox_id)` | Security Council | Destroy sandbox environment |

#### Sandbox Events

| # | Event | Description |
|---|-------|-------------|
| 4 | `SANDBOX.Created` | Sandbox created for worker |
| 5 | `SANDBOX.Destroyed` | Sandbox destroyed |
| 6 | `SANDBOX.IsolationViolation` | Isolation boundary violated |

---

## 5. Institutions

### 5.1 WCS â€” Worker Communication Service

**Source:** `Bible/03-Institutions/Workers/004-WCS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | RPC | `sendMessage(sender_id, target_id, message_type, payload)` | Capability-based | Send message from one Worker to another |
| 2 | RPC | `broadcastMessage(sender_id, mission_id, message_type, payload)` | Capability-based | Broadcast message to all Workers in mission |
| 3 | RPC | `publishMessage(sender_id, topic, payload)` | Capability-based | Publish message to topic |
| 4 | RPC | `sendMessageWithResponse(...)` | Capability-based | Send message and wait for response |
| 5 | RPC | `receiveMessage(session_id, message_id?)` | Capability-based | Dequeue next message |
| 6 | RPC | `subscribeTopic(session_id, topic, filter_criteria?)` | Capability-based | Subscribe to a topic |
| 7 | RPC | `unsubscribeTopic(subscription_id)` | Capability-based | Unsubscribe from a topic |
| 8 | RPC | `getMessageHistory(session_id, time_range, filters?)` | Capability-based | Query message history |
| 9 | RPC | `getPendingMessages(session_id)` | Capability-based | List undelivered messages |
| 10 | Interface | `MessageChannel` | N/A | All communication patterns implement this |
| 11 | Message | `WorkerMessage` | N/A | message_id, sender_id, target_id, message_type, payload, ttl |

#### WCS Events

| # | Event | Description |
|---|-------|-------------|
| 12 | `WCS.MessageSent` | Worker sends a message |
| 13 | `WCS.MessageDelivered` | Message reaches target |
| 14 | `WCS.MessageFailed` | Message delivery fails |
| 15 | `WCS.MessageExpired` | Message TTL exceeded |
| 16 | `WCS.MessageDropped` | Queue overflow message dropped |
| 17 | `WCS.MessageAuthorizationDenied` | Cross-scope message denied |
| 18 | `WCS.SubscriptionCreated` | Worker subscribes to a topic |
| 19 | `WCS.SubscriptionRemoved` | Worker unsubscribes |
| 20 | `WCS.BroadcastSent` | Broadcast message transmitted |

---

### 5.2 WSS â€” Worker Security Service

**Source:** `Bible/03-Institutions/Workers/003-WSS.md`

| # | Event | Description |
|---|-------|-------------|
| 1 | `WSS.IsolationViolation` | Worker violates isolation boundary |
| 2 | `WSS.BoundaryCrossingAttempt` | Worker attempts cross-boundary access |
| 3 | `WSS.ResourceExhaustion` | Worker exceeds resource quota |
| 4 | `WSS.CapabilityViolation` | Worker attempts action outside capability scope |
| 5 | `WSS.IsolationConfigured` | Worker isolation configuration changed |
| 6 | `WSS.IsolationValidated` | Isolation layers are verified |
| 7 | `WSS.BoundaryEnforced` | Enforcement action taken on boundary violation |
| 8 | `WSS.CommunicationSpoofAttempt` | Worker attempts to spoof another Worker's identity |

---

### 5.3 Playbook Manager

**Source:** `Bible/03-Institutions/Workers/005-Playbook-Manager.md`

| # | Event | Description |
|---|-------|-------------|
| 1 | `PLAYBOOK.Created` | New playbook is created |
| 2 | `PLAYBOOK.Validated` | Playbook passes validation |
| 3 | `PLAYBOOK.Published` | Playbook is published |
| 4 | `PLAYBOOK.Deprecated` | Playbook is deprecated |
| 5 | `PLAYBOOK.Archived` | Playbook is archived |
| 6 | `PLAYBOOK.ExecutionStarted` | Playbook execution begins |
| 7 | `PLAYBOOK.ExecutionApproved` | Execution request is approved |
| 8 | `PLAYBOOK.ExecutionRejected` | Execution request is denied |
| 9 | `PLAYBOOK.StepCompleted` | Individual step finishes |
| 10 | `PLAYBOOK.StepFailed` | Step encounters error |
| 11 | `PLAYBOOK.RollbackInitiated` | Rollback plan begins execution |
| 12 | `PLAYBOOK.RollbackCompleted` | Rollback finishes |
| 13 | `PLAYBOOK.ExecutionCompleted` | Playbook execution finishes successfully |
| 14 | `PLAYBOOK.ExecutionFailed` | Execution fails (unrecoverable) |
| 15 | `PLAYBOOK.ExecutionCancelled` | Execution is cancelled mid-run |

---

### 5.4 OIS â€” Organization Interaction Service

**Source:** `Bible/03-Institutions/Organizations/006-OIS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `InteractionChannel` | N/A | All communication patterns implement this |
| 2 | ACF Topic | `org.research.findings` | ACF | Cross-Organization research findings subscription |
| 3 | ACF Topic | Org-wide broadcast topic | ACF | Cross-Organization broadcast |

#### OIS Events

| # | Event | Description |
|---|-------|-------------|
| 4 | `OIS.RequestSent` | Cross-Org request is sent |
| 5 | `OIS.RequestResponded` | Request receives response |
| 6 | `OIS.RequestDeclined` | Request is declined |
| 7 | `OIS.SubscriptionCreated` | Org subscribes to a topic |
| 8 | `OIS.SubscriptionRemoved` | Org unsubscribes |
| 9 | `OIS.AgreementReached` | Cross-Org agreement is finalized |
| 10 | `OIS.AgreementExpired` | Cross-Org agreement expires |
| 11 | `OIS.KnowledgeShared` | Knowledge is shared between Orgs |
| 12 | `OIS.AuthorizationDenied` | Cross-Org message authorization fails |

---

## 6. Runtime

### 6.1 Execution Runtime SDK

**Source:** `Bible/04-Execution/Runtime/001-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `ExecutionProvider` | Execution token | Interface all execution providers implement |
| 2 | Method | `providerId()` | N/A | Returns provider identity |
| 3 | Method | `providerVersion()` | N/A | Returns provider version |
| 4 | Method | `supportedActionTypes()` | N/A | Returns supported action types |
| 5 | Method | `capabilityDeclaration()` | N/A | Returns capability declaration |
| 6 | Method | `initialize(config)` | N/A | Initialize provider with configuration |
| 7 | Method | `health()` | N/A | Returns provider health status |
| 8 | Method | `shutdown()` | N/A | Graceful shutdown |
| 9 | Method | `execute(context)` | VerificationToken | Execute an action (core contract) |
| 10 | Method | `executeStream(context)` | VerificationToken | Streaming execution |

#### Runtime Messages / Types

| # | Type | Name | Description |
|---|------|------|-------------|
| 11 | Message | `ExecutionContext` | execution_id, token, action, capability_bounds, autonomy_level, parent_entity_id, deadline |
| 12 | Message | `ExecutionResult` | execution_id, status, output, metrics, error, events |
| 13 | Stream Chunk | `ExecutionChunk` | sequence, data, progress, is_final, metrics |

#### Runtime Events

| # | Event | Description |
|---|-------|-------------|
| 14 | `Runtime.ProviderRegistered` | Provider registered with Runtime Manager |
| 15 | `Runtime.ProviderHealthChanged` | Provider health status changes |
| 16 | `Runtime.ProviderExecutionStarted` | Provider execution starts |
| 17 | `Runtime.ProviderResourceWarning` | Provider resource warning |
| 18 | `Runtime.ProviderExecutionCompleted` | Provider execution completed |
| 19 | `Runtime.ProviderExecutionFailed` | Provider execution failed |
| 20 | `Runtime.ProviderBoundsExceeded` | Provider bounds exceeded |
| 21 | `Runtime.ProviderShutdown` | Provider shutdown |

---

### 6.2 Ollama Integration

**Source:** `Bible/04-Execution/Runtime/004-Ollama.md`

| # | Type | Endpoint | Auth | Description |
|---|------|----------|------|-------------|
| 1 | REST | `POST {endpoint}/api/generate` | Network-bound (localhost/private) | Ollama model generation endpoint |
| 2 | REST | `POST {endpoint}/api/chat` | Network-bound (localhost/private) | Ollama chat endpoint |

---

### 6.3 Runtime SDK (Interface Layer)

**Source:** `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 1 | Interface | `RuntimeProvider` | mTLS | Interface for runtime execution providers |
| 2 | Method | `createSession(genome, allocation)` | Execution token | Create Worker session |
| 3 | Method | `startSession(sessionId)` | Execution token | Start session |
| 4 | Method | `pauseSession(sessionId)` | Execution token | Pause session |
| 5 | Method | `resumeSession(sessionId)` | Execution token | Resume session |
| 6 | Method | `terminateSession(sessionId)` | Execution token | Terminate session |
| 7 | Method | `invokeCapability(sessionId, capability, input)` | Execution token | Execute capability |
| 8 | Method | `cancelInvocation(sessionId, invocationId)` | Execution token | Cancel invocation |
| 9 | Method | `getSessionStatus(sessionId)` | Execution token | Query session state |
| 10 | Method | `streamMetrics(sessionId)` | Execution token | Subscribe to metrics |
| 11 | Method | `healthCheck()` | N/A | Report provider health |
| 12 | Method | `reportUsage(sessionId)` | Execution token | Report resource usage |

#### ACF Endpoints

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 13 | `acf://runtime-provider-id/control` | ACF | Runtime provider control endpoint |
| 14 | `acf://runtime-provider-id/metrics` | ACF | Runtime provider metrics endpoint |
| 15 | `acf://runtime-provider-id/events` | ACF | Runtime provider events endpoint |

#### Runtime SDK Events

| # | Event | Description |
|---|-------|-------------|
| 16 | `SDK.RuntimeSessionCreated` | Runtime session created |
| 17 | `SDK.RuntimeSessionStarted` | Session transitions to Running |
| 18 | `SDK.RuntimeSessionPaused` | Session paused |
| 19 | `SDK.RuntimeSessionTerminated` | Session terminates |
| 20 | `SDK.RuntimeInvocationCompleted` | Capability invocation finishes |
| 21 | `SDK.RuntimeHealthChanged` | Provider health changes |
| 22 | `SDK.RuntimeUsageReported` | Resource usage reported |

---

### 6.4 Audit SDK

**Source:** `Bible/08-Interfaces/SDK/001-Audit-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `queryEvents(filter)` | audit scope | Query Events by filter criteria |
| 2 | `getEventById(eventId)` | audit scope | Retrieve single Event |
| 3 | `streamEvents(filter)` | audit scope | Subscribe to Event stream |
| 4 | `verifyChain(eventId)` | audit scope | Verify Event chain integrity |
| 5 | `verifyIntegrity(eventRange)` | audit scope | Verify Event range integrity |
| 6 | `computeHash(eventId)` | audit scope | Compute cryptographic hash |
| 7 | `analyzePattern(filter, pattern)` | audit scope | Detect patterns across Events |
| 8 | `computeAggregation(filter, metric)` | audit scope | Aggregate metrics |
| 9 | `detectAnomaly(filter, baseline)` | audit scope | Detect anomalous patterns |
| 10 | `checkCompliance(filter, standard)` | audit scope | Check compliance |
| 11 | `generateEvidencePackage(caseId, filter)` | audit scope | Generate evidence package |
| 12 | `produceReport(template, filter)` | audit scope | Produce audit report |
| 13 | `registerAsObserver()` | audit scope | Register as event observer |
| 14 | `setRetentionPolicy(policy)` | audit scope | Set retention policy |
| 15 | `getRetentionPolicy()` | audit scope | Get current retention policy |

---


## 7. Domains

### 7.1 Trading

**Source:** `Bible/07-Domains/Trading/000-Overview.md`

| # | Event | Description |
|---|-------|-------------|
| 1 | `Trading.StrategyResearched` | Strategy research completes |
| 2 | `Trading.BacktestRun` | Backtest execution finishes |
| 3 | `Trading.PaperTradeCompleted` | Paper trading phase finishes |
| 4 | `Trading.StrategyDeployed` | Strategy is deployed to live trading |
| 5 | `Trading.OrderPlaced` | Order is submitted to exchange |
| 6 | `Trading.OrderFilled` | Order execution confirmed |
| 7 | `Trading.OrderRejected` | Order is rejected by exchange or risk |
| 8 | `Trading.RiskLimitBreached` | A risk limit is approached or breached |
| 9 | `Trading.StrategyRetired` | Strategy is decommissioned |

---

### 7.2 Security Domain

**Source:** `Bible/07-Domains/Security/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 1 | Capability | `monitor_endpoints` | Security domain worker capability â€” monitor endpoints |
| 2 | Capability | `analyze_network` | Security domain worker capability â€” analyze network traffic |
| 3 | Capability | `detect_intrusion` | Security domain worker capability â€” detect intrusion |
| 4 | Capability | `alert_triage` | Security domain worker capability â€” triage alerts |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 5 | `Security.VulnerabilityFound` | Potential vulnerability identified |
| 6 | `Security.VulnerabilityVerified` | Vulnerability confirmed in sandbox |
| 7 | `Security.ExploitAttempted` | Exploit verification executed |
| 8 | `Security.IncidentDetected` | Security incident is identified |
| 9 | `Security.IncidentContained` | Incident containment completed |
| 10 | `Security.IncidentResolved` | Incident fully resolved |
| 11 | `Security.IntelReportGenerated` | Threat intelligence report produced |
| 12 | `Security.ComplianceAuditRun` | Compliance audit completes |

---

## 8. Federation

### 8.1 AIP â€” Agent Interoperability Protocol

**Source:** `Bible/06-Services/Federation/001-AIP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `connectToRemoteAgent(remote_session_id, instance_id)` | mTLS + identity | Initiate cross-instance session |
| 2 | `sendAgentMessage(session_id, message)` | mTLS + identity | Send message to remote session |
| 3 | `disconnectAgent(session_id)` | mTLS | Terminate cross-instance session |
| 4 | `getAgentStatus(session_id)` | mTLS | Check remote session status |

#### AIP Events

| # | Event | Description |
|---|-------|-------------|
| 5 | `AIP.AgentConnected` | Remote session connected |
| 6 | `AIP.AgentDisconnected` | Remote session disconnected |
| 7 | `AIP.MessageSent` | Message transmitted |
| 8 | `AIP.MessageReceived` | Message received |
| 9 | `AIP.ConnectionFailed` | Connection attempt failed |

---

### 8.2 SXP â€” Security Exchange Protocol

**Source:** `Bible/06-Services/Federation/007-SXP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 1 | `shareThreat(threat_data, severity)` | mTLS + signature | Share threat intelligence |
| 2 | `subscribeThreats(filter, callback_endpoint)` | mTLS | Subscribe to threat feed |
| 3 | `acknowledgeThreat(threat_id, action_taken)` | mTLS | Acknowledge receipt of threat |
| 4 | `escalateThreat(threat_id, escalation_reason)` | Security Council | Request coordinated response |
| 5 | `getThreatStatus(threat_id)` | mTLS | Query threat resolution status |

#### SXP Events

| # | Event | Description |
|---|-------|-------------|
| 6 | `SXP.ThreatShared` | Threat intelligence shared |
| 7 | `SXP.ThreatAcknowledged` | Receipt acknowledged |
| 8 | `SXP.ThreatEscalated` | Threat escalated |
| 9 | `SXP.ThreatResolved` | Threat resolved |
| 10 | `SXP.SubscriptionCreated` | Threat feed subscription |

---

## 9. Governance

| # | Type | Source | Description |
|---|------|--------|-------------|
| 1 | Event | `Bible/01-Governance/001-CLS.md` | CLS constitutional amendment lifecycle events |
| 2 | Event | `Bible/01-Governance/002-DGP.md` | DGP decision assessed events |
| 3 | Event | `Bible/01-Governance/003-CRP.md` | CRP constitutional review proposal events |
| 4 | RPC (ACF) | `Bible/01-Governance/004-CKR.md` | CKR constitutional knowledge registry query interface |
| 5 | Event | `Bible/01-Governance/004-CKR.md` | CKR knowledge registry lifecycle events |
| 6 | Event | `Bible/01-Governance/005-ADG.md` | ADG architecture decision events |
| 7 | Event | `Bible/01-Governance/006-AKM.md` | AKM knowledge management lifecycle events |

---

## 10. Cross-Cutting

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 1 | Interface | `AuthMethod` | `Bible/00-Foundations/002-Design-DNA.md` | Interface for implementing new authentication methods |
| 2 | Event | `Lifecycle.StateChanged` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity state transitioned |
| 3 | Event | `Lifecycle.TransitionDenied` | `Bible/00-Foundations/008-Object-Lifecycle.md` | State transition denied |
| 4 | Event | `Lifecycle.EntityCreated` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity created |
| 5 | Event | `Lifecycle.EntityCompleted` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity lifecycle completed |
| 6 | Event | `Lifecycle.EntityArchived` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity archived |
| 7 | Schema | Canonical API Envelope | `Bible/08-Interfaces/API/000-Specifications.md` | Standard envelope: api_version, message_id, correlation_id, timestamp, source_entity_id, target_entity_id, auth_token, payload |
| 8 | Schema | Error Response Schema | `Bible/08-Interfaces/API/000-Specifications.md` | Standard error: code, message, details, correlation_id |

#### Framework API Events

| # | Event | Description |
|---|-------|-------------|
| 9 | `API.ContractPublished` | New API contract registered |
| 10 | `API.ContractDeprecated` | API version deprecated |
| 11 | `API.RequestProcessed` | API request completes |
| 12 | `API.RateLimitExceeded` | Rate limit exceeded |
| 13 | `API.SchemaValidationFailed` | Schema validation failed |

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
