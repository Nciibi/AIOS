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

### 1.3 EPG â€” Event Processing Graph

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

### 1.4 EIP â€” External Integration Protocol

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

### 1.5 CP â€” Credential Provider

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

### 1.7 LMS â€” Lifecycle Management Service

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

### 2.1 Academy â€” Knowledge Management

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

### 2.2 Academy â€” Knowledge Search (REST Gateway)

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

### 2.3 Academy â€” KMS Query Interface

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

### 2.4 Academy â€” Knowledge SDK Provider Interface

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

### 3.1 Sou â€” Executive Intelligence

**Source:** `Bible/02-Core/Brain/Sou/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 157 | Interface | `SouIdentity` | Sou's persistent identity â€” name, purpose, history |
| 158 | Interface | `SouPersonality` | Sou's behavioral traits, values, communication style |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 159 | `Sou.InputReceived` | Input entered Sou's processing |
| 160 | `Sou.DecisionMade` | Sou made a strategic decision |
| 161 | `Sou.MissionCreated` | Sou created a mission |
| 162 | `Sou.ResponseSent` | Sou sent a user-facing response |

---

### 3.2 LLMOS â€” AI Inference Pipeline

**Source:** `Bible/02-Core/Brain/LLMOS/`

#### RPC Methods (via ACF â€” `acf://llmos/inference`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 163 | `inference(request)` | Execution token | Full pipeline inference â€” non-streaming |
| 164 | `inferenceStream(request)` | Execution token | Full pipeline inference â€” streaming |
| 165 | `embed(inputs, model)` | Execution token | Generate embeddings |
| 166 | `countTokens(content, model)` | Execution token | Count tokens for content on specific model |
| 167 | `getModelStatus()` | ACF-level | Get status of all registered models |

#### Pipeline Events (Gateway)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 168 | `LLMOS.RequestReceived` | 000-Overview.md | Request entered pipeline |
| 169 | `LLMOS.SecurityChecked` | 000-Overview.md | Security Council verification passed |
| 170 | `LLMOS.RateChecked` | 000-Overview.md | Rate limit check passed |
| 171 | `LLMOS.BudgetChecked` | 006-Token-Budget-Manager.md | Token budget verified |
| 172 | `LLMOS.BudgetReconciled` | 006-Token-Budget-Manager.md | Budget reconciled after request |
| 173 | `LLMOS.RequestCompleted` | 000-Overview.md | Pipeline completed successfully |
| 174 | `LLMOS.RequestFailed` | 000-Overview.md | Pipeline failed |

#### Pipeline Events (Pre-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 175 | `LLMOS.ModelsResolved` | 001-Model-Registry.md | Model candidates matched requirements |
| 176 | `LLMOS.ModelSelected` | 002-Router.md | Router selected optimal model |
| 177 | `LLMOS.ModelRegistered` | 001-Model-Registry.md | New model registered |
| 178 | `LLMOS.ModelDeregistered` | 001-Model-Registry.md | Model deregistered |
| 179 | `LLMOS.ModelUpdated` | 001-Model-Registry.md | Model health/metrics updated |
| 180 | `LLMOS.ProviderRegistered` | 013-Provider-SDK.md | Provider initialized |
| 181 | `LLMOS.ProviderDeregistered` | 013-Provider-SDK.md | Provider shut down |
| 182 | `LLMOS.ProviderHealthChanged` | 001-Model-Registry.md | Provider health transitioned |
| 183 | `LLMOS.CostOptimized` | 007-Cost-Optimizer.md | Cost estimation and optimization complete |
| 184 | `LLMOS.CacheHit` | 011-Cache.md | Cache lookup hit |
| 185 | `LLMOS.CacheMiss` | 011-Cache.md | Cache lookup miss |
| 186 | `LLMOS.CacheStored` | 011-Cache.md | Response cached |
| 187 | `LLMOS.CacheEvicted` | 011-Cache.md | Cache entry evicted |
| 188 | `LLMOS.ContextBuilt` | 004-Context-Builder.md | Context window assembled |
| 189 | `LLMOS.MemoryInjected` | 005-Memory-Injection.md | Memories injected into context |
| 190 | `LLMOS.PromptCompiled` | 003-Prompt-Compiler.md | Prompt compiled from template |
| 191 | `LLMOS.GuardrailChecked` | 010-Guardrails.md | Guardrail evaluation (input or output) |

#### Pipeline Events (Execution)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 192 | `LLMOS.ProviderCalled` | 009-Retry-Engine.md | Provider API call made |
| 193 | `LLMOS.ProviderRetry` | 009-Retry-Engine.md | Retry triggered on provider error |
| 194 | `LLMOS.CircuitBreakerOpened` | 009-Retry-Engine.md | Circuit breaker opened for model |
| 195 | `LLMOS.CircuitBreakerClosed` | 009-Retry-Engine.md | Circuit breaker closed for model |
| 196 | `LLMOS.StreamChunk` | 008-Streaming-Manager.md | Stream chunk emitted |
| 197 | `LLMOS.StreamCompleted` | 008-Streaming-Manager.md | Stream terminated |
| 198 | `LLMOS.StreamError` | 008-Streaming-Manager.md | Mid-stream error occurred |

#### Pipeline Events (Post-Processing)

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 199 | `LLMOS.ResponseValidated` | 012-Response-Validator.md | Response passed validation |
| 200 | `LLMOS.ResponseValidationFailed` | 012-Response-Validator.md | Response failed validation |
| 201 | `LLMOS.ResponseValidationRetry` | 012-Response-Validator.md | Validation retry triggered |

#### Model Provider Interfaces (SDK)

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 202 | Interface | `ModelProvider` | 013-Provider-SDK.md | Interface for AI model providers |
| 203 | Method | `initialize(config)` | 013-Provider-SDK.md | Initialize provider with config |
| 204 | Method | `healthCheck()` | 013-Provider-SDK.md | Report provider health |
| 205 | Method | `shutdown()` | 013-Provider-SDK.md | Graceful shutdown |
| 206 | Method | `listModels()` | 013-Provider-SDK.md | List available models |
| 207 | Method | `execute(request)` | 013-Provider-SDK.md | Execute model inference |
| 208 | Method | `executeStream(request)` | 013-Provider-SDK.md | Execute streaming inference |
| 209 | Method | `embed(inputs, model)` | 013-Provider-SDK.md | Generate embeddings |
| 210 | Method | `countTokens(content, model)` | 013-Provider-SDK.md | Count tokens for content |

#### Schemas

| # | Schema | Source | Description |
|---|--------|--------|-------------|
| 211 | `InferenceRequest` | 000-Overview.md | Full LLMOS request envelope |
| 212 | `InferenceResponse` | 000-Overview.md | Full LLMOS response envelope |
| 213 | `LLMOSChunk` | 008-Streaming-Manager.md | Streaming chunk schema |
| 214 | `ModelRequirements` | 000-Overview.md | Model selection constraints |
| 215 | `MemoryConfig` | 000-Overview.md | Memory retrieval configuration |
| 216 | `CachePolicy` | 011-Cache.md | Cache read/write behavior |
| 217 | `ModelEntry` | 001-Model-Registry.md | Registered model record |
| 218 | `CompiledPrompt` | 003-Prompt-Compiler.md | Compiled prompt structure |
| 219 | `ContextPayload` | 004-Context-Builder.md | Context window payload |
| 220 | `RetryConfig` | 009-Retry-Engine.md | Retry and fallback configuration |
| 221 | `GuardrailRule` | 010-Guardrails.md | Guardrail rule definition |
| 222 | `ProviderRequest` | 013-Provider-SDK.md | Provider-level request format |
| 223 | `ProviderResponse` | 013-Provider-SDK.md | Provider-level response format |
| 224 | `ProviderError` | 013-Provider-SDK.md | Provider error structure |
| 225 | `EntityTokenBudget` | 006-Token-Budget-Manager.md | Entity token budget structure |
| 226 | `CostEstimate` | 007-Cost-Optimizer.md | Cost estimation structure |
| 227 | `PromptTemplate` | 003-Prompt-Compiler.md | Prompt template definition |

---

### 3.3 DTS â€” Decision & Trust Scoring

**Source:** `Bible/02-Core/DTS/001-Architecture.md`, `Bible/02-Core/DTS/003-Sim-Engines.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 228 | Interface | `DecisionEvaluator` | Interface for evaluating decisions |
| 229 | Interface | `EvaluationResult` | Interface for evaluation results |
| 230 | Interface | `TrustScorer` | Interface for trust scoring |
| 231 | Interface | `TrustScore` | Interface for trust score data |
| 232 | Interface | `SimEngine` | All simulation engines implement this |

---

### 3.4 ROS â€” Resource Orchestration

**Source:** `Bible/02-Core/ROS/008-Provider-SDK.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 233 | Interface | `ResourceProvider` | SDK interface that all resource providers must implement |

---

## 4. Security Council

The Security Council is the constitutional authority for all security operations. It operates the 7-stage verification pipeline that gates every action before execution. See `Bible/04-Execution/Security/` for full specifications.

### 4.1 Verification Pipeline (Execution-Auth)

**Source:** `Bible/04-Execution/Security/Execution-Auth/000-EAS.md`

The 7-stage pipeline enforces Law 8 (Verification-First). Every action passes through all stages before receiving an execution token.

| # | Stage | Service | Function |
|---|-------|---------|----------|
| 234 | 1 â€” Identity | IDS | Verify actor identity exists and is active |
| 235 | 2 â€” Authentication | ATS | Verify authentication token is valid |
| 236 | 3 â€” Authorization | AZS | Verify actor is authorized for this action |
| 237 | 4 â€” Policy | Policy System | Verify action complies with active policies |
| 238 | 5 â€” Capability | CCA | Verify actor has required capabilities |
| 239 | 6 â€” Risk | Risk Engine | Evaluate risk level; escalate if above threshold |
| 240 | 7 â€” Execution Auth | Execution-Auth | Issue execution token; reserve resources via ROS |

#### Pipeline Events

| # | Event | Description |
|---|-------|-------------|
| 241 | `SC.PipelineStarted` | Action entered verification pipeline |
| 242 | `SC.StagePassed` | Individual pipeline stage passed |
| 243 | `SC.StageFailed` | Individual pipeline stage failed |
| 244 | `SC.PipelineCompleted` | All 7 stages passed, execution token issued |
| 245 | `SC.PipelineDenied` | Action denied at a pipeline stage |
| 246 | `SC.ExecutionTokenIssued` | Execution authorization token created |
| 247 | `SC.ExecutionTokenRevoked` | Execution token revoked before use |

---

### 4.2 IDS â€” Identity Service

**Source:** `Bible/04-Execution/Security/IDS/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 248 | Interface | `IdentityFactory` | Security Council | Create new identities |
| 249 | Interface | `IdentityRegistry` | Security Council | Register, resolve, and manage identity records |
| 250 | RPC | `createIdentity(entity_type, attributes)` | Security Council | Create a new constitutional identity |
| 251 | RPC | `resolveIdentity(entity_id)` | ACF-level | Resolve identity to its current attributes |
| 252 | RPC | `validateIdentity(entity_id)` | ACF-level | Verify identity is active and valid |
| 253 | RPC | `deprecateIdentity(entity_id, reason)` | Security Council | Deprecate an identity |

#### IDS Events

| # | Event | Description |
|---|-------|-------------|
| 254 | `IDS.IdentityCreated` | New identity registered |
| 255 | `IDS.IdentityResolved` | Identity resolution completed |
| 256 | `IDS.IdentityDeprecated` | Identity deprecated |
| 257 | `IDS.IdentitySuspended` | Identity temporarily suspended |

---

### 4.3 ATS â€” Authentication Token Service

**Source:** `Bible/04-Execution/Security/ATS/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 258 | Interface | `AuthProvider` | Security Council | All authentication methods implement this |
| 259 | RPC | `authenticate(entity_id, credentials)` | None (pre-auth) | Authenticate entity; return session token |
| 260 | RPC | `validateToken(token)` | ACF-level | Validate existing authentication token |
| 261 | RPC | `revokeToken(token)` | Security Council | Revoke an authentication token |
| 262 | RPC | `requestMFA(entity_id, method)` | ACF-level | Request multi-factor authentication |
| 263 | RPC | `verifyMFA(entity_id, challenge_response)` | ACF-level | Verify MFA challenge response |

#### ATS Events

| # | Event | Description |
|---|-------|-------------|
| 264 | `ATS.Authenticated` | Entity authenticated successfully |
| 265 | `ATS.AuthenticationFailed` | Authentication attempt failed |
| 266 | `ATS.MFARequired` | MFA challenge issued |
| 267 | `ATS.MFAVerified` | MFA challenge passed |
| 268 | `ATS.TokenIssued` | Authentication token issued |
| 269 | `ATS.TokenRevoked` | Token revoked |
| 270 | `ATS.TokenExpired` | Token expired naturally |

---

### 4.4 AZS â€” Authorization Service

**Source:** `Bible/04-Execution/Security/AZS/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 271 | Interface | `AuthorizationProvider` | Security Council | All authorization methods implement this |
| 272 | RPC | `checkPermission(entity_id, action, resource)` | Pipeline | Check RBAC permission |
| 273 | RPC | `checkABAC(entity_id, action, resource, context)` | Pipeline | Check attribute-based access control |
| 274 | RPC | `checkCapability(entity_id, capability_id)` | Pipeline | Check capability-based authorization |
| 275 | RPC | `assignRole(entity_id, role)` | Security Council | Assign a role to an entity |
| 276 | RPC | `revokeRole(entity_id, role)` | Security Council | Revoke a role from an entity |

#### AZS Events

| # | Event | Description |
|---|-------|-------------|
| 277 | `AZS.Authorized` | Authorization check passed |
| 278 | `AZS.Denied` | Authorization check denied |
| 279 | `AZS.RoleAssigned` | Role assigned to entity |
| 280 | `AZS.RoleRevoked` | Role revoked from entity |

---

### 4.5 Policy System

**Source:** `Bible/04-Execution/Security/Policy-System/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 281 | Interface | `PolicyEngine` | Security Council | Policy definition and evaluation engine |
| 282 | RPC | `createPolicy(policy_def)` | Security Council | Create a new policy |
| 283 | RPC | `evaluatePolicy(policy_id, context)` | Pipeline | Evaluate action against policy |
| 284 | RPC | `activatePolicy(policy_id)` | Security Council | Activate a policy |
| 285 | RPC | `deactivatePolicy(policy_id)` | Security Council | Deactivate a policy |
| 286 | RPC | `listPolicies(filter?)` | ACF-level | List policies matching filter |

#### Policy Events

| # | Event | Description |
|---|-------|-------------|
| 287 | `POL.PolicyCreated` | New policy defined |
| 288 | `POL.PolicyActivated` | Policy activated |
| 289 | `POL.PolicyDeactivated` | Policy deactivated |
| 290 | `POL.PolicyEvaluated` | Policy evaluation completed |
| 291 | `POL.PolicyViolation` | Action violates a policy |

---

### 4.6 Risk Engine

**Source:** `Bible/04-Execution/Security/Risk/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 292 | Interface | `RiskScorer` | Security Council | Risk scoring interface |
| 293 | RPC | `evaluateRisk(entity_id, action, context)` | Pipeline | Compute risk score for action |
| 294 | RPC | `getRiskProfile(entity_id)` | Security Council | Get entity's current risk profile |
| 295 | RPC | `escalateRisk(action_id, reason)` | Security Council | Escalate a high-risk action |

#### Risk Events

| # | Event | Description |
|---|-------|-------------|
| 296 | `RSK.RiskScored` | Risk score computed for action |
| 297 | `RSK.ThresholdExceeded` | Risk score exceeded configured threshold |
| 298 | `RSK.RiskEscalated` | Action escalated for manual review |

---

### 4.7 EAS â€” Evidence Audit Service

**Source:** `Bible/04-Execution/Security/Audit/000-EAS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 299 | Interface | `EvidenceStore` | Security Council | Immutable evidence storage backend |
| 300 | Interface | `EvidenceQuery` | Security Council | Evidence query interface |
| 301 | RPC | `sealEvidence(record)` | Pipeline | Seal an evidence record |
| 302 | RPC | `queryEvidence(query)` | Auditor | Query evidence records |
| 303 | RPC | `exportEvidence(query, format)` | Auditor | Export evidence for external audit |

#### EAS Events

| # | Event | Description |
|---|-------|-------------|
| 304 | `EAS.EvidenceSealed` | New evidence record sealed |
| 305 | `EAS.EvidenceQueried` | Evidence query executed |
| 306 | `EAS.EvidenceExported` | Evidence export completed |

---

### 4.8 CSP â€” Cryptographic Service Provider

**Source:** `Bible/04-Execution/Security/Crypto/`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 307 | Interface | `CryptoProvider` | Security Council | Cryptographic operations interface |
| 308 | RPC | `generateKey(algorithm, purpose)` | Security Council | Generate cryptographic key pair |
| 309 | RPC | `sign(entity_id, payload)` | Security Council | Sign payload with entity key |
| 310 | RPC | `verify(entity_id, payload, signature)` | ACF-level | Verify signature |
| 311 | RPC | `encrypt(payload, recipient_id)` | ACF-level | Encrypt payload for recipient |
| 312 | RPC | `decrypt(ciphertext)` | Security Council | Decrypt ciphertext |
| 313 | RPC | `hash(payload, algorithm)` | ACF-level | Compute cryptographic hash |

#### CSP Events

| # | Event | Description |
|---|-------|-------------|
| 314 | `CSP.KeyGenerated` | New key pair generated |
| 315 | `CSP.KeyRotated` | Key rotated |
| 316 | `CSP.KeyCompromised` | Key reported compromised |
| 317 | `CSP.SignatureVerified` | Signature verification completed |
| 318 | `CSP.EncryptionPerformed` | Encryption operation completed |

---

### 4.9 SSM â€” Session & Secret Management

**Source:** `Bible/04-Execution/Security/SSM/000-SSM.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 319 | Interface | `SessionManager` | Security Council | Session lifecycle management |
| 320 | Interface | `SecretStore` | Security Council | Encrypted secret storage |
| 321 | RPC | `createSession(entity_id, ttl)` | ACF-level | Create new session |
| 322 | RPC | `validateSession(session_id)` | ACF-level | Validate session is active |
| 323 | RPC | `terminateSession(session_id)` | Security Council | Terminate a session |
| 324 | RPC | `storeSecret(name, value, ttl)` | Security Council | Store an encrypted secret |
| 325 | RPC | `resolveSecret(name)` | Security Council | Resolve a secret (for authorized callers) |
| 326 | RPC | `rotateSecret(name)` | Security Council | Rotate a secret |
| 327 | RPC | `revokeSecret(name)` | Security Council | Revoke a secret |

#### SSM Events

| # | Event | Description |
|---|-------|-------------|
| 328 | `SSM.SessionCreated` | New session created |
| 329 | `SSM.SessionTerminated` | Session terminated |
| 330 | `SSM.SessionExpired` | Session TTL exceeded |
| 331 | `SSM.SecretStored` | Secret encrypted and stored |
| 332 | `SSM.SecretRotated` | Secret rotated |
| 333 | `SSM.SecretRevoked` | Secret revoked |

---

### 4.10 Sandbox â€” Execution Isolation

**Source:** `Bible/04-Execution/Security/Sandbox/000-Isolation.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 334 | Interface | `SandboxProvider` | Security Council | Execution isolation interface |
| 335 | RPC | `createSandbox(worker_id, resource_limits)` | Pipeline | Create isolated execution environment |
| 336 | RPC | `destroySandbox(sandbox_id)` | Security Council | Destroy sandbox environment |

#### Sandbox Events

| # | Event | Description |
|---|-------|-------------|
| 337 | `SANDBOX.Created` | Sandbox created for worker |
| 338 | `SANDBOX.Destroyed` | Sandbox destroyed |
| 339 | `SANDBOX.IsolationViolation` | Isolation boundary violated |

---

## 5. Institutions

### 5.1 WCS â€” Worker Communication Service

**Source:** `Bible/03-Institutions/Workers/004-WCS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 340 | RPC | `sendMessage(sender_id, target_id, message_type, payload)` | Capability-based | Send message from one Worker to another |
| 341 | RPC | `broadcastMessage(sender_id, mission_id, message_type, payload)` | Capability-based | Broadcast message to all Workers in mission |
| 342 | RPC | `publishMessage(sender_id, topic, payload)` | Capability-based | Publish message to topic |
| 343 | RPC | `sendMessageWithResponse(...)` | Capability-based | Send message and wait for response |
| 344 | RPC | `receiveMessage(session_id, message_id?)` | Capability-based | Dequeue next message |
| 345 | RPC | `subscribeTopic(session_id, topic, filter_criteria?)` | Capability-based | Subscribe to a topic |
| 346 | RPC | `unsubscribeTopic(subscription_id)` | Capability-based | Unsubscribe from a topic |
| 347 | RPC | `getMessageHistory(session_id, time_range, filters?)` | Capability-based | Query message history |
| 348 | RPC | `getPendingMessages(session_id)` | Capability-based | List undelivered messages |
| 349 | Interface | `MessageChannel` | N/A | All communication patterns implement this |
| 350 | Message | `WorkerMessage` | N/A | message_id, sender_id, target_id, message_type, payload, ttl |

#### WCS Events

| # | Event | Description |
|---|-------|-------------|
| 351 | `WCS.MessageSent` | Worker sends a message |
| 352 | `WCS.MessageDelivered` | Message reaches target |
| 353 | `WCS.MessageFailed` | Message delivery fails |
| 354 | `WCS.MessageExpired` | Message TTL exceeded |
| 355 | `WCS.MessageDropped` | Queue overflow message dropped |
| 356 | `WCS.MessageAuthorizationDenied` | Cross-scope message denied |
| 357 | `WCS.SubscriptionCreated` | Worker subscribes to a topic |
| 358 | `WCS.SubscriptionRemoved` | Worker unsubscribes |
| 359 | `WCS.BroadcastSent` | Broadcast message transmitted |

---

### 5.2 WSS â€” Worker Security Service

**Source:** `Bible/03-Institutions/Workers/003-WSS.md`

| # | Event | Description |
|---|-------|-------------|
| 360 | `WSS.IsolationViolation` | Worker violates isolation boundary |
| 361 | `WSS.BoundaryCrossingAttempt` | Worker attempts cross-boundary access |
| 362 | `WSS.ResourceExhaustion` | Worker exceeds resource quota |
| 363 | `WSS.CapabilityViolation` | Worker attempts action outside capability scope |
| 364 | `WSS.IsolationConfigured` | Worker isolation configuration changed |
| 365 | `WSS.IsolationValidated` | Isolation layers are verified |
| 366 | `WSS.BoundaryEnforced` | Enforcement action taken on boundary violation |
| 367 | `WSS.CommunicationSpoofAttempt` | Worker attempts to spoof another Worker's identity |

---

### 5.3 Playbook Manager

**Source:** `Bible/03-Institutions/Workers/005-Playbook-Manager.md`

| # | Event | Description |
|---|-------|-------------|
| 368 | `PLAYBOOK.Created` | New playbook is created |
| 369 | `PLAYBOOK.Validated` | Playbook passes validation |
| 370 | `PLAYBOOK.Published` | Playbook is published |
| 371 | `PLAYBOOK.Deprecated` | Playbook is deprecated |
| 372 | `PLAYBOOK.Archived` | Playbook is archived |
| 373 | `PLAYBOOK.ExecutionStarted` | Playbook execution begins |
| 374 | `PLAYBOOK.ExecutionApproved` | Execution request is approved |
| 375 | `PLAYBOOK.ExecutionRejected` | Execution request is denied |
| 376 | `PLAYBOOK.StepCompleted` | Individual step finishes |
| 377 | `PLAYBOOK.StepFailed` | Step encounters error |
| 378 | `PLAYBOOK.RollbackInitiated` | Rollback plan begins execution |
| 379 | `PLAYBOOK.RollbackCompleted` | Rollback finishes |
| 380 | `PLAYBOOK.ExecutionCompleted` | Playbook execution finishes successfully |
| 381 | `PLAYBOOK.ExecutionFailed` | Execution fails (unrecoverable) |
| 382 | `PLAYBOOK.ExecutionCancelled` | Execution is cancelled mid-run |

---

### 5.4 OIS â€” Organization Interaction Service

**Source:** `Bible/03-Institutions/Organizations/006-OIS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 383 | Interface | `InteractionChannel` | N/A | All communication patterns implement this |
| 384 | ACF Topic | `org.research.findings` | ACF | Cross-Organization research findings subscription |
| 385 | ACF Topic | Org-wide broadcast topic | ACF | Cross-Organization broadcast |

#### OIS Events

| # | Event | Description |
|---|-------|-------------|
| 386 | `OIS.RequestSent` | Cross-Org request is sent |
| 387 | `OIS.RequestResponded` | Request receives response |
| 388 | `OIS.RequestDeclined` | Request is declined |
| 389 | `OIS.SubscriptionCreated` | Org subscribes to a topic |
| 390 | `OIS.SubscriptionRemoved` | Org unsubscribes |
| 391 | `OIS.AgreementReached` | Cross-Org agreement is finalized |
| 392 | `OIS.AgreementExpired` | Cross-Org agreement expires |
| 393 | `OIS.KnowledgeShared` | Knowledge is shared between Orgs |
| 394 | `OIS.AuthorizationDenied` | Cross-Org message authorization fails |

---

## 6. Runtime

### 6.1 Execution Runtime SDK

**Source:** `Bible/04-Execution/Runtime/001-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 395 | Interface | `ExecutionProvider` | Execution token | Interface all execution providers implement |
| 396 | Method | `providerId()` | N/A | Returns provider identity |
| 397 | Method | `providerVersion()` | N/A | Returns provider version |
| 398 | Method | `supportedActionTypes()` | N/A | Returns supported action types |
| 399 | Method | `capabilityDeclaration()` | N/A | Returns capability declaration |
| 400 | Method | `initialize(config)` | N/A | Initialize provider with configuration |
| 401 | Method | `health()` | N/A | Returns provider health status |
| 402 | Method | `shutdown()` | N/A | Graceful shutdown |
| 403 | Method | `execute(context)` | VerificationToken | Execute an action (core contract) |
| 404 | Method | `executeStream(context)` | VerificationToken | Streaming execution |

#### Runtime Messages / Types

| # | Type | Name | Description |
|---|------|------|-------------|
| 405 | Message | `ExecutionContext` | execution_id, token, action, capability_bounds, autonomy_level, parent_entity_id, deadline |
| 406 | Message | `ExecutionResult` | execution_id, status, output, metrics, error, events |
| 407 | Stream Chunk | `ExecutionChunk` | sequence, data, progress, is_final, metrics |

#### Runtime Events

| # | Event | Description |
|---|-------|-------------|
| 408 | `Runtime.ProviderRegistered` | Provider registered with Runtime Manager |
| 409 | `Runtime.ProviderHealthChanged` | Provider health status changes |
| 410 | `Runtime.ProviderExecutionStarted` | Provider execution starts |
| 411 | `Runtime.ProviderResourceWarning` | Provider resource warning |
| 412 | `Runtime.ProviderExecutionCompleted` | Provider execution completed |
| 413 | `Runtime.ProviderExecutionFailed` | Provider execution failed |
| 414 | `Runtime.ProviderBoundsExceeded` | Provider bounds exceeded |
| 415 | `Runtime.ProviderShutdown` | Provider shutdown |

---

### 6.2 Ollama Integration

**Source:** `Bible/04-Execution/Runtime/004-Ollama.md`

| # | Type | Endpoint | Auth | Description |
|---|------|----------|------|-------------|
| 416 | REST | `POST {endpoint}/api/generate` | Network-bound (localhost/private) | Ollama model generation endpoint |
| 417 | REST | `POST {endpoint}/api/chat` | Network-bound (localhost/private) | Ollama chat endpoint |

---

### 6.3 Runtime SDK (Interface Layer)

**Source:** `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 418 | Interface | `RuntimeProvider` | mTLS | Interface for runtime execution providers |
| 419 | Method | `createSession(genome, allocation)` | Execution token | Create Worker session |
| 420 | Method | `startSession(sessionId)` | Execution token | Start session |
| 421 | Method | `pauseSession(sessionId)` | Execution token | Pause session |
| 422 | Method | `resumeSession(sessionId)` | Execution token | Resume session |
| 423 | Method | `terminateSession(sessionId)` | Execution token | Terminate session |
| 424 | Method | `invokeCapability(sessionId, capability, input)` | Execution token | Execute capability |
| 425 | Method | `cancelInvocation(sessionId, invocationId)` | Execution token | Cancel invocation |
| 426 | Method | `getSessionStatus(sessionId)` | Execution token | Query session state |
| 427 | Method | `streamMetrics(sessionId)` | Execution token | Subscribe to metrics |
| 428 | Method | `healthCheck()` | N/A | Report provider health |
| 429 | Method | `reportUsage(sessionId)` | Execution token | Report resource usage |

#### ACF Endpoints

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 430 | `acf://runtime-provider-id/control` | ACF | Runtime provider control endpoint |
| 431 | `acf://runtime-provider-id/metrics` | ACF | Runtime provider metrics endpoint |
| 432 | `acf://runtime-provider-id/events` | ACF | Runtime provider events endpoint |

#### Runtime SDK Events

| # | Event | Description |
|---|-------|-------------|
| 433 | `SDK.RuntimeSessionCreated` | Runtime session created |
| 434 | `SDK.RuntimeSessionStarted` | Session transitions to Running |
| 435 | `SDK.RuntimeSessionPaused` | Session paused |
| 436 | `SDK.RuntimeSessionTerminated` | Session terminates |
| 437 | `SDK.RuntimeInvocationCompleted` | Capability invocation finishes |
| 438 | `SDK.RuntimeHealthChanged` | Provider health changes |
| 439 | `SDK.RuntimeUsageReported` | Resource usage reported |

---

### 6.4 Audit SDK

**Source:** `Bible/08-Interfaces/SDK/001-Audit-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 440 | `queryEvents(filter)` | audit scope | Query Events by filter criteria |
| 441 | `getEventById(eventId)` | audit scope | Retrieve single Event |
| 442 | `streamEvents(filter)` | audit scope | Subscribe to Event stream |
| 443 | `verifyChain(eventId)` | audit scope | Verify Event chain integrity |
| 444 | `verifyIntegrity(eventRange)` | audit scope | Verify Event range integrity |
| 445 | `computeHash(eventId)` | audit scope | Compute cryptographic hash |
| 446 | `analyzePattern(filter, pattern)` | audit scope | Detect patterns across Events |
| 447 | `computeAggregation(filter, metric)` | audit scope | Aggregate metrics |
| 448 | `detectAnomaly(filter, baseline)` | audit scope | Detect anomalous patterns |
| 449 | `checkCompliance(filter, standard)` | audit scope | Check compliance |
| 450 | `generateEvidencePackage(caseId, filter)` | audit scope | Generate evidence package |
| 451 | `produceReport(template, filter)` | audit scope | Produce audit report |
| 452 | `registerAsObserver()` | audit scope | Register as event observer |
| 453 | `setRetentionPolicy(policy)` | audit scope | Set retention policy |
| 454 | `getRetentionPolicy()` | audit scope | Get current retention policy |

---


## 7. Domains

### 7.1 Trading

**Source:** `Bible/07-Domains/Trading/000-Overview.md`

| # | Event | Description |
|---|-------|-------------|
| 455 | `Trading.StrategyResearched` | Strategy research completes |
| 456 | `Trading.BacktestRun` | Backtest execution finishes |
| 457 | `Trading.PaperTradeCompleted` | Paper trading phase finishes |
| 458 | `Trading.StrategyDeployed` | Strategy is deployed to live trading |
| 459 | `Trading.OrderPlaced` | Order is submitted to exchange |
| 460 | `Trading.OrderFilled` | Order execution confirmed |
| 461 | `Trading.OrderRejected` | Order is rejected by exchange or risk |
| 462 | `Trading.RiskLimitBreached` | A risk limit is approached or breached |
| 463 | `Trading.StrategyRetired` | Strategy is decommissioned |

---

### 7.2 Security Domain

**Source:** `Bible/07-Domains/Security/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 464 | Capability | `monitor_endpoints` | Security domain worker capability â€” monitor endpoints |
| 465 | Capability | `analyze_network` | Security domain worker capability â€” analyze network traffic |
| 466 | Capability | `detect_intrusion` | Security domain worker capability â€” detect intrusion |
| 467 | Capability | `alert_triage` | Security domain worker capability â€” triage alerts |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 468 | `Security.VulnerabilityFound` | Potential vulnerability identified |
| 469 | `Security.VulnerabilityVerified` | Vulnerability confirmed in sandbox |
| 470 | `Security.ExploitAttempted` | Exploit verification executed |
| 471 | `Security.IncidentDetected` | Security incident is identified |
| 472 | `Security.IncidentContained` | Incident containment completed |
| 473 | `Security.IncidentResolved` | Incident fully resolved |
| 474 | `Security.IntelReportGenerated` | Threat intelligence report produced |
| 475 | `Security.ComplianceAuditRun` | Compliance audit completes |

---

## 8. Federation

### 8.1 AIP â€” Agent Interoperability Protocol

**Source:** `Bible/06-Services/Federation/001-AIP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 476 | `connectToRemoteAgent(remote_session_id, instance_id)` | mTLS + identity | Initiate cross-instance session |
| 477 | `sendAgentMessage(session_id, message)` | mTLS + identity | Send message to remote session |
| 478 | `disconnectAgent(session_id)` | mTLS | Terminate cross-instance session |
| 479 | `getAgentStatus(session_id)` | mTLS | Check remote session status |

#### AIP Events

| # | Event | Description |
|---|-------|-------------|
| 480 | `AIP.AgentConnected` | Remote session connected |
| 481 | `AIP.AgentDisconnected` | Remote session disconnected |
| 482 | `AIP.MessageSent` | Message transmitted |
| 483 | `AIP.MessageReceived` | Message received |
| 484 | `AIP.ConnectionFailed` | Connection attempt failed |

---

### 8.2 SXP â€” Security Exchange Protocol

**Source:** `Bible/06-Services/Federation/007-SXP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 485 | `shareThreat(threat_data, severity)` | mTLS + signature | Share threat intelligence |
| 486 | `subscribeThreats(filter, callback_endpoint)` | mTLS | Subscribe to threat feed |
| 487 | `acknowledgeThreat(threat_id, action_taken)` | mTLS | Acknowledge receipt of threat |
| 488 | `escalateThreat(threat_id, escalation_reason)` | Security Council | Request coordinated response |
| 489 | `getThreatStatus(threat_id)` | mTLS | Query threat resolution status |

#### SXP Events

| # | Event | Description |
|---|-------|-------------|
| 490 | `SXP.ThreatShared` | Threat intelligence shared |
| 491 | `SXP.ThreatAcknowledged` | Receipt acknowledged |
| 492 | `SXP.ThreatEscalated` | Threat escalated |
| 493 | `SXP.ThreatResolved` | Threat resolved |
| 494 | `SXP.SubscriptionCreated` | Threat feed subscription |

---

## 9. Governance

| # | Type | Source | Description |
|---|------|--------|-------------|
| 495 | Event | `Bible/01-Governance/001-CLS.md` | CLS constitutional amendment lifecycle events |
| 496 | Event | `Bible/01-Governance/002-DGP.md` | DGP decision assessed events |
| 497 | Event | `Bible/01-Governance/003-CRP.md` | CRP constitutional review proposal events |
| 498 | RPC (ACF) | `Bible/01-Governance/004-CKR.md` | CKR constitutional knowledge registry query interface |
| 499 | Event | `Bible/01-Governance/004-CKR.md` | CKR knowledge registry lifecycle events |
| 500 | Event | `Bible/01-Governance/005-ADG.md` | ADG architecture decision events |
| 501 | Event | `Bible/01-Governance/006-AKM.md` | AKM knowledge management lifecycle events |

---

## 10. Cross-Cutting

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 502 | Interface | `AuthMethod` | `Bible/00-Foundations/002-Design-DNA.md` | Interface for implementing new authentication methods |
| 503 | Event | `Lifecycle.StateChanged` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity state transitioned |
| 504 | Event | `Lifecycle.TransitionDenied` | `Bible/00-Foundations/008-Object-Lifecycle.md` | State transition denied |
| 505 | Event | `Lifecycle.EntityCreated` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity created |
| 506 | Event | `Lifecycle.EntityCompleted` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity lifecycle completed |
| 507 | Event | `Lifecycle.EntityArchived` | `Bible/00-Foundations/008-Object-Lifecycle.md` | Entity archived |
| 508 | Schema | Canonical API Envelope | `Bible/08-Interfaces/API/000-Specifications.md` | Standard envelope: api_version, message_id, correlation_id, timestamp, source_entity_id, target_entity_id, auth_token, payload |
| 509 | Schema | Error Response Schema | `Bible/08-Interfaces/API/000-Specifications.md` | Standard error: code, message, details, correlation_id |

#### Framework API Events

| # | Event | Description |
|---|-------|-------------|
| 510 | `API.ContractPublished` | New API contract registered |
| 511 | `API.ContractDeprecated` | API version deprecated |
| 512 | `API.RequestProcessed` | API request completes |
| 513 | `API.RateLimitExceeded` | Rate limit exceeded |
| 514 | `API.SchemaValidationFailed` | Schema validation failed |

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
