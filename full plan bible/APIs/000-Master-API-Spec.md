# AIOS Master API Specification

> **Purpose:** Single-source-of-truth registry for every concrete API endpoint, ACF topic, RPC method, streaming channel, interface method, and event type across the entire AIOS platform.
> **Framework Spec:** `Bible/08-Interfaces/API/000-Specifications.md` (API design conventions, versioning, error schemas)
> **Status:** Registry — catalogs what exists; does not prescribe design.

---

## Table of Contents

1. [Platform Services](#1-platform-services)
2. [Core Engines](#2-core-engines)
3. [Security Council](#3-security-council)
4. [Institutions](#4-institutions)
5. [Runtime](#5-runtime)
6. [Domains](#6-domains)
7. [Federation](#7-federation)
8. [Governance](#8-governance)
9. [Cross-Cutting](#9-cross-cutting)
10. [Appendix: Schema Index](#10-appendix-schema-index)

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
| 12 | `PSAP.HeartbeatReceived` | Heartbeat received from service |
| 13 | `PSAP.ServiceRegistered` | Service registered |
| 14 | `PSAP.ServiceDeregistered` | Service deregistered |
| 15 | `PSAP.ServiceHealthChanged` | Service health status changed |

---

### 1.2 EVS — Event Store

**Source:** `Bible/05-Platform/004-EVS.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 16 | `appendEvent(stream_id, event_type, data, metadata)` | ACF token | Append event to stream |
| 17 | `readStream(stream_id, from_version?, to_version?)` | ACF token | Read events from stream |
| 18 | `readStreamByTime(stream_id, from_time, to_time)` | ACF token | Read events by time range |
| 19 | `readEventByVersion(stream_id, version)` | ACF token | Read specific event version |
| 20 | `subscribeStream(stream_id, subscriber)` | ACF token | Subscribe to event stream |
| 21 | `getEventCount(stream_id)` | ACF token | Get event count |
| 22 | `getStreamInfo(stream_id)` | ACF token | Get stream info |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 23 | `EVS.EventAppended` | Event written to stream |
| 24 | `EVS.StreamCreated` | Event stream initialized |
| 25 | `EVS.SnapshotCreated` | Snapshot taken |
| 26 | `EVS.SubscriptionActivated` | Subscriber subscribed to stream |
| 27 | `EVS.ReadReplicaAdded` | Read replica came online |

---

### 1.3 EPG — Event Processing Graph

**Source:** `Bible/05-Platform/006-EPG.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 28 | Stream | Event Processing Graph (EPG) | ACF-level | DAG-based event stream processing (filter, transform, enrich, aggregate, route) |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 29 | `EPG.GraphDefined` | New processing graph defined |
| 30 | `EPG.GraphDeployed` | Processing graph deployed |
| 31 | `EPG.GraphUndeployed` | Processing graph undeployed |
| 32 | `EPG.NodeProcessed` | Graph node completed processing |
| 33 | `EPG.PipelineStarted` | Pipeline execution started |
| 34 | `EPG.PipelineCompleted` | Pipeline execution completed |
| 35 | `EPG.PipelineFailed` | Pipeline execution failed |

---

### 1.4 EIP — External Integration Protocol

**Source:** `Bible/05-Platform/007-EIP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 36 | Interface | `Connector` | N/A | All EIP connectors implement this interface |
| 37 | REST/gRPC/AMQP/MQTT | External Integration Protocol | mTLS (varies) | Protocol for webhook, Kafka, MQTT, AMQP, REST, gRPC connectors |

#### Messages

| # | Message | Description |
|---|---------|-------------|
| 38 | `ConnectorConfig` | Protocol, endpoint, format, authentication config |

---

### 1.5 CP — Credential Provider

**Source:** `Bible/05-Platform/012-CP.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 39 | Interface | `Credential` | All credential types implement this |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 40 | `CP.CredentialIssued` | Credential generated |

---

### 1.6 Graph Framework

**Source:** `Bible/05-Platform/013-Graph-Framework.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 41 | Interface | `GraphStore` | N/A | All graph storage backends implement this |
| 42 | RPC (ACF) | Graph Framework operations | ACF-level | Graph queries via ACF |

---

### 1.7 LMS — Lifecycle Management Service

**Source:** `Bible/05-Platform/000-LMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 43 | RPC (ACF) | LMS transition requests | ACF token | Entity lifecycle state transitions via ACF |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 44 | `LMS.EntityCreated` | Entity created |
| 45 | `LMS.EntityStateChanged` | Entity state transitioned |
| 46 | `LMS.EntityCompleted` | Entity lifecycle completed |
| 47 | `LMS.EntityArchived` | Entity archived |
| 48 | `LMS.TransitionRejected` | State transition rejected |

---

## 2. Core Engines

### 2.1 Academy — Knowledge Management

**Source:** `Bible/02-Core/Academy/016-Knowledge-API.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 49 | `academy.knowledge.create` | `knowledge.propose` | Propose a new knowledge artifact |
| 50 | `academy.knowledge.validate` | `knowledge.validate` | Trigger validation of knowledge artifact |
| 51 | `academy.knowledge.accept` | `knowledge.accept` | Accept validated knowledge into Registry |
| 52 | `academy.knowledge.query` | `knowledge.query` | Query knowledge artifacts by graph traversal |
| 53 | `academy.knowledge.search` | `knowledge.query` | Full-text, semantic, or faceted search |
| 54 | `academy.knowledge.get` | `knowledge.query` | Retrieve specific knowledge artifact by ID |
| 55 | `academy.knowledge.provenance` | `knowledge.query` | Get full provenance chain for artifact |
| 56 | `academy.knowledge.list` | `knowledge.query` | List knowledge artifacts with filters |
| 57 | `academy.knowledge.deprecate` | `knowledge.deprecate` | Deprecate a knowledge artifact |
| 58 | `academy.knowledge.compose` | `knowledge.compose.{method}` | Request KCE knowledge composition |
| 59 | `academy.knowledge.execute` | `knowledge.execute.{type}` | Request KEE knowledge execution |

#### Pub-Sub (ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 60 | `academy.knowledge.subscribe` | `knowledge.subscribe` | Subscribe to knowledge lifecycle events |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 61 | `API.RequestReceived` | API received a request |
| 62 | `API.RequestCompleted` | API completed processing |
| 63 | `API.RequestFailed` | API encountered an error |
| 64 | `API.RateLimitExceeded` | Rate limit exceeded |
| 65 | `API.SubscriptionCreated` | Subscription created |
| 66 | `API.SubscriptionRemoved` | Subscription removed |

---

### 2.2 Academy — Knowledge Search (REST Gateway)

**Source:** `Bible/02-Core/Academy/010-Knowledge-Search.md`

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 67 | `GET /search?q=...&fields=...&operator=...` | JWT | Full-text knowledge search |
| 68 | `GET /search?q=...&type=semantic&top_k=...` | JWT | Semantic knowledge search |
| 69 | `GET /search?type=graph&start_node_id=...&edge_types=...&max_depth=...` | JWT | Graph-based knowledge search |
| 70 | `GET /search?type=operational&organization_id=...&tags=...&confidence_min=...` | JWT | Faceted/operational knowledge search |

---

### 2.3 Academy — KMS Query Interface

**Source:** `Bible/02-Core/Academy/002-KMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 71 | RPC (ACF) | KMS query interface | ACF-level | Knowledge management storage and retrieval queries |

---

### 2.4 Academy — Knowledge SDK Provider Interface

**Source:** `Bible/02-Core/Academy/015-Knowledge-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 72 | `authenticate(entity_id, credentials)` | ACF token | Authenticate with ATS and obtain session token |
| 73 | `setIdentity(identity)` | ACF token | Set identity for subsequent operations |
| 74 | `getCurrentEntity()` | ACF token | Returns authenticated entity info |
| 75 | `hasCapability(capability)` | ACF token | Check if entity has a specific capability |
| 76 | `search(query, options)` | ACF token | Full-text and semantic search |
| 77 | `getKnowledge(id)` | ACF token | Retrieve artifact by ID |
| 78 | `listKnowledge(filters)` | ACF token | List artifacts matching filters |
| 79 | `getProvenance(id, options)` | ACF token | Get provenance chain |
| 80 | `queryGraph(query)` | ACF token | Graph traversal query |
| 81 | `subscribe(topic, callback)` | ACF token | Subscribe to knowledge events |
| 82 | `unsubscribe(subscriptionId)` | ACF token | Unsubscribe from events |
| 83 | `onKnowledgeAccepted(callback)` | ACF token | Convenience subscription for accepted events |
| 84 | `onKnowledgeDeprecated(callback)` | ACF token | Convenience subscription for deprecation events |
| 85 | `proposeKnowledge(artifact)` | ACF token | Submit knowledge for validation |
| 86 | `getProposalStatus(proposalId)` | ACF token | Check proposal status |
| 87 | `withdrawProposal(proposalId)` | ACF token | Withdraw a pending proposal |
| 88 | `resubmitKnowledge(proposalId, updatedArtifact)` | ACF token | Resubmit with revisions |
| 89 | `composeUnion(artifactIds)` | ACF token | Union composition |
| 90 | `composeIntersection(artifactIds)` | ACF token | Intersection composition |
| 91 | `composeAnalogy(sourceId, targetDomain)` | ACF token | Analogy composition |
| 92 | `composeInduction(artifactIds)` | ACF token | Induction composition |
| 93 | `composeDeduction(principleId, context)` | ACF token | Deduction composition |
| 94 | `getCompositionStatus(requestId)` | ACF token | Check composition request status |
| 95 | `executeKnowledge(knowledgeId, context)` | ACF token | Execute a knowledge artifact |
| 96 | `getExecutionStatus(executionId)` | ACF token | Check execution status |
| 97 | `cancelExecution(executionId)` | ACF token | Cancel a pending execution |
| 98 | `getExecutionResult(executionId)` | ACF token | Get execution result |

#### SDK Events

| # | Event | Description |
|---|-------|-------------|
| 99 | `SDK.Authenticated` | SDK successfully authenticates |
| 100 | `SDK.QueryExecuted` | SDK executes a query |
| 101 | `SDK.KnowledgeProposed` | SDK proposes knowledge |
| 102 | `SDK.EventSubscribed` | SDK subscribes to a topic |
| 103 | `SDK.EventReceived` | SDK receives an event |
| 104 | `SDK.ErrorEncountered` | SDK encounters an error |

---

### 2.5 Sou — Reasoning Engine

**Source:** `Bible/02-Core/Sou/001-Reasoning.md`, `Bible/02-Core/Sou/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 105 | Interface | `Reasoner` | All reasoning methods implement this |
| 106 | Interface | `SouEngine` | Common interface for Planner, Reasoning, Missions, Learning, Knowledge |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 107 | `Sou.ReasoningFailed` | Reasoning encountered an error |

---

### 2.6 DTS — Decision & Trust Scoring

**Source:** `Bible/02-Core/DTS/001-Architecture.md`, `Bible/02-Core/DTS/003-Sim-Engines.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 108 | Interface | `DecisionEvaluator` | Interface for evaluating decisions |
| 109 | Interface | `EvaluationResult` | Interface for evaluation results |
| 110 | Interface | `TrustScorer` | Interface for trust scoring |
| 111 | Interface | `TrustScore` | Interface for trust score data |
| 112 | Interface | `SimEngine` | All simulation engines implement this |

---

### 2.7 ROS — Resource Orchestration

**Source:** `Bible/02-Core/ROS/008-Provider-SDK.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 113 | Interface | `ResourceProvider` | SDK interface that all resource providers must implement |

---

## 3. Security Council

### 3.1 ACF — Anticipatory Communication Fabric

**Source:** `Bible/06-Services/ACF/`

#### 3.1.1 Messaging (`002-Messages.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 114 | `sendMessage(envelope, payload)` | auth_token | Send a message |
| 115 | `sendMessageWithAck(envelope, payload, timeout)` | auth_token | Send with acknowledgement |
| 116 | `receiveMessage(entity_id, timeout?)` | auth_token | Receive a message |
| 117 | `getMessageStatus(message_id)` | auth_token | Get message delivery status |
| 118 | `retryMessage(message_id)` | auth_token | Retry failed message |
| 119 | `deadLetterMessage(message_id, reason)` | auth_token | Move to dead letter queue |
| 120 | `acknowledgeMessage(message_id)` | auth_token | Acknowledge message |
| 121 | `rejectMessage(message_id, reason)` | auth_token | Reject message |

#### 3.1.2 Routing (`003-Routing.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 122 | `defineRoute(target_pattern, endpoints, config)` | Security Council | Define routing rule |
| 123 | `updateRoute(route_id, updates)` | Security Council | Update routing rule |
| 124 | `removeRoute(route_id)` | Security Council | Remove routing rule |
| 125 | `resolveRoute(target, sender?)` | ACF-level | Resolve target to endpoint |
| 126 | `getRoute(route_id)` | ACF-level | Get route entry |
| 127 | `listRoutes(filter?)` | ACF-level | List routing entries |
| 128 | `testRoute(target, message?)` | ACF-level | Test route resolution |

#### 3.1.3 Subscriptions (`004-Subscriptions.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 129 | `subscribe(entity_id, topic_pattern, subscription_type, config)` | ACF-level | Subscribe to topic |
| 130 | `unsubscribe(subscription_id)` | ACF-level | Unsubscribe from topic |
| 131 | `publish(topic, message)` | ACF-level | Publish message to topic |
| 132 | `listSubscriptions(entity_id)` | ACF-level | List subscriptions |
| 133 | `listSubscribers(topic)` | ACF-level | List subscribers of topic |
| 134 | `getSubscriptionStatus(subscription_id)` | ACF-level | Get subscription status |
| 135 | `updateSubscription(subscription_id, updates)` | ACF-level | Update subscription configuration |

#### Canonical ACF Topic Names

| # | Topic Pattern | Description |
|---|--------------|-------------|
| 136 | `academy.knowledge.accepted` | Knowledge accepted events |
| 137 | `academy.knowledge.rejected` | Knowledge rejected events |
| 138 | `academy.knowledge.revised` | Knowledge revised events |
| 139 | `lifecycle.state.changed` | Lifecycle state changes |
| 140 | `lifecycle.entity.created` | Entity created |
| 141 | `lifecycle.entity.completed` | Entity completed |
| 142 | `security.auth.authenticated` | Auth success events |
| 143 | `security.auth.authorized` | Auth authorized events |
| 144 | `security.auth.denied` | Auth denied events |
| 145 | `system.session.created` | Session created |
| 146 | `system.session.destroyed` | Session destroyed |
| 147 | `aios/{domain}/{service}/{instance}/health` | Health check topic for all services |

#### 3.1.4 Streaming (`005-Streaming.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 148 | `createStream(topic, partitions, config)` | ACF-level | Create a stream |
| 149 | `deleteStream(stream_id)` | ACF-level | Delete a stream |
| 150 | `publishToStream(topic, message, partition_key?)` | ACF-level | Publish to stream |
| 151 | `publishToPartition(stream_id, partition_id, message)` | ACF-level | Publish to specific partition |
| 152 | `consumeStream(stream_id, consumer_group, consumer_id)` | ACF-level | Consume from stream |
| 153 | `getStreamPosition(consumer_group, consumer_id, partition_id?)` | ACF-level | Get stream position |
| 154 | `seekStream(consumer_group, consumer_id, position)` | ACF-level | Seek to position |
| 155 | `commitPosition(consumer_group, consumer_id, partition_id, sequence)` | ACF-level | Commit consumer position |
| 156 | `getStreamInfo(stream_id)` | ACF-level | Get stream info |
| 157 | `listStreams(filter?)` | ACF-level | List streams |

#### 3.1.5 Reliability / DLQ (`006-Reliability.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 158 | `configureRetry(topic_pattern, retry_policy)` | Security Council | Configure retry policy |
| 159 | `getRetryStatus(message_id)` | ACF-level | Get retry status |
| 160 | `getDeadLetterMessages(filter?)` | Security Council | List DLQ messages |
| 161 | `replayDeadLetter(dlq_message_id, new_target?)` | Security Council | Replay DLQ message |
| 162 | `replayAllDeadLetter(filter?)` | Security Council | Replay all DLQ messages |
| 163 | `purgeDeadLetter(filter?)` | Security Council | Purge DLQ messages |
| 164 | `getDeadLetterStats()` | Security Council | Get DLQ statistics |
| 165 | `getDeadLetterMessage(dlq_message_id)` | Security Council | Get specific DLQ message |

#### 3.1.6 Distributed / Instance Federation (`007-Distributed.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 166 | `connectInstance(instance_url, credentials, config)` | mTLS X.509 | Connect to remote ACF instance |
| 167 | `disconnectInstance(bridge_id)` | mTLS | Disconnect remote instance |
| 168 | `syncRoutingTable(bridge_id)` | mTLS | Sync routing tables |
| 169 | `getInstanceStatus(instance_id)` | mTLS | Get remote instance status |
| 170 | `listConnectedInstances()` | mTLS | List all connected instances |
| 171 | `updateBandwidth(bridge_id, bandwidth_bps)` | Security Council | Update bridge bandwidth |
| 172 | `updateExportPolicy(bridge_id, policy)` | Security Council | Update route export policy |

#### ACF Messages

| # | Message | Description |
|---|---------|-------------|
| 173 | `Message` (envelope + payload) | Fundamental unit of communication |
| 174 | `Envelope` | Routing and metadata (version, message_id, sender, target, timestamp, ttl, priority, delivery_mode) |
| 175 | `DeliveryStatus` | Message delivery status tracking |
| 176 | `DeliveryAttempt` | Delivery attempt record |
| 177 | `DeadLetterMessage` | Undeliverable message with failure metadata |
| 178 | `DeliveryFailure` | Delivery failure details |
| 179 | `RetryPolicy` | Retry policy configuration |

#### ACF Events

| # | Event | Source File | Description |
|---|-------|-------------|-------------|
| 180 | `ACF.MessageSent` | 002-Messages | Sender dispatches message |
| 181 | `ACF.MessageAuthenticated` | 002-Messages | Token verified |
| 182 | `ACF.MessageAuthorized` | 002-Messages | Route permitted |
| 183 | `ACF.MessageQueued` | 002-Messages | Message persisted |
| 184 | `ACF.MessageRouted` | 002-Messages | Target endpoint selected |
| 185 | `ACF.MessageDelivered` | 002-Messages | Message reaches receiver |
| 186 | `ACF.MessageAcknowledged` | 002-Messages | Receiver confirms |
| 187 | `ACF.MessageFailed` | 002-Messages | Permanent delivery failure |
| 188 | `ACF.MessageExpired` | 002-Messages | TTL exceeded |
| 189 | `ACF.RouteDefined` | 003-Routing | Route created |
| 190 | `ACF.RouteUpdated` | 003-Routing | Route modified |
| 191 | `ACF.RouteRemoved` | 003-Routing | Route deleted |
| 192 | `ACF.EndpointUnavailable` | 003-Routing | Endpoint becomes unhealthy |
| 193 | `ACF.EndpointRestored` | 003-Routing | Endpoint becomes healthy |
| 194 | `ACF.RouteUnresolvable` | 003-Routing | No route matches |
| 195 | `ACF.RoutingTableSynced` | 003-Routing | Routing table synchronized |
| 196 | `ACF.SubscriptionCreated` | 004-Subscriptions | Subscription created |
| 197 | `ACF.SubscriptionActivated` | 004-Subscriptions | Subscription activated |
| 198 | `ACF.SubscriptionPaused` | 004-Subscriptions | Subscription paused |
| 199 | `ACF.SubscriptionResumed` | 004-Subscriptions | Subscription resumed |
| 200 | `ACF.SubscriptionUnsubscribed` | 004-Subscriptions | Subscription ended |
| 201 | `ACF.MessagePublished` | 004-Subscriptions | Message published to topic |
| 202 | `ACF.SubscriptionDelivered` | 004-Subscriptions | Message delivered to subscriber |
| 203 | `ACF.BackpressureApplied` | 004-Subscriptions | Slow subscriber throttled |
| 204 | `ACF.FilterEvaluated` | 004-Subscriptions | Filter predicate evaluated |
| 205 | `ACF.StreamCreated` | 005-Streaming | Stream created |
| 206 | `ACF.StreamDeleted` | 005-Streaming | Stream deleted |
| 207 | `ACF.PartitionReassigned` | 005-Streaming | Partition reassigned |
| 208 | `ACF.ConsumerAdded` | 005-Streaming | Consumer joins group |
| 209 | `ACF.ConsumerRemoved` | 005-Streaming | Consumer leaves |
| 210 | `ACF.ConsumerRebalanced` | 005-Streaming | Group rebalanced |
| 211 | `ACF.StreamEnd` | 005-Streaming | Stream reaches end |
| 212 | `ACF.PositionCommitted` | 005-Streaming | Consumer commits position |
| 213 | `ACF.RetryPolicyConfigured` | 006-Reliability | Retry policy set |
| 214 | `ACF.DeliveryAttempted` | 006-Reliability | Delivery attempt made |
| 215 | `ACF.DeliverySucceeded` | 006-Reliability | Delivery succeeds |
| 216 | `ACF.DeliveryFailed` | 006-Reliability | Delivery fails |
| 217 | `ACF.MessageDeadLettered` | 006-Reliability | Message sent to DLQ |
| 218 | `ACF.DLQReplayed` | 006-Reliability | DLQ message replayed |
| 219 | `ACF.DLQPurged` | 006-Reliability | DLQ messages purged |
| 220 | `ACF.ReliabilityThresholdBreached` | 006-Reliability | Reliability target missed |
| 221 | `ACF.DLQReviewed` | 006-Reliability | DLQ review completed |
| 222 | `ACF.InstanceConnected` | 007-Distributed | ACF bridge established |
| 223 | `ACF.InstanceDisconnected` | 007-Distributed | Bridge torn down |
| 224 | `ACF.InstancePartitioned` | 007-Distributed | Network partition detected |
| 225 | `ACF.InstanceReconnected` | 007-Distributed | Partition healed |
| 226 | `ACF.RoutingTableSynced` | 007-Distributed | Routing tables synchronized |
| 227 | `ACF.CrossInstanceMessageSent` | 007-Distributed | Message crosses instance boundary |
| 228 | `ACF.CrossInstanceMessageReceived` | 007-Distributed | Message received from remote |
| 229 | `ACF.HopLimitExceeded` | 007-Distributed | Message exceeds max hops |
| 230 | `ACF.BandwidthExceeded` | 007-Distributed | Bandwidth limit hit |
| 231 | `ACF.ClusterNodeJoined` | 001-Architecture | New node joins ACF cluster |
| 232 | `ACF.ClusterNodeLeft` | 001-Architecture | Node leaves cluster |
| 233 | `ACF.ClusterLeaderElected` | 001-Architecture | New Raft leader elected |
| 234 | `ACF.TopicPartitionCreated` | 001-Architecture | Topic partition created |
| 235 | `ACF.TopicPartitionReassigned` | 001-Architecture | Partition reassigned |

---

### 3.2 AZS — Authorization Services

**Source:** `Bible/04-Execution/Security/AZS/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 236 | Interface | `Permission` | 000-RBAC.md | Permission definition interface |
| 237 | Interface | `ABACPolicy` | 001-ABAC.md | Attribute-based access control policy interface |
| 238 | Interface | `Capability` | 002-Capability.md | Capability token interface |

#### AZS Events

| # | Event | Description |
|---|-------|-------------|
| 239 | `AZS.CapabilityIssued` | Capability created |
| 240 | `AZS.CapabilityPresented` | Capability presented for verification |
| 241 | `AZS.CapabilityVerified` | Capability passes verification |
| 242 | `AZS.CapabilityDenied` | Capability fails verification |
| 243 | `AZS.CapabilityRevoked` | Capability revoked |
| 244 | `AZS.CapabilityExpired` | Capability expired |
| 245 | `AZS.DelegationExtended` | Delegation extended |
| 246 | `AZS.CapabilityConsumed` | One-time capability consumed |

---

### 3.3 SSM — Session & Secret Management

**Source:** `Bible/04-Execution/Security/SSM/000-SSM.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 247 | Interface | `Session` | Session model interface |
| 248 | Interface | `SessionToken` | Session token interface |
| 249 | Interface | `Secret` | Secret model interface |

#### SSM Events

| # | Event | Description |
|---|-------|-------------|
| 250 | `SSM.SessionCreated` | New session created |
| 251 | `SSM.SessionAuthenticated` | Session authenticated |
| 252 | `SSM.SessionTerminated` | Session terminated |
| 253 | `SSM.SessionSuspended` | Session suspended |
| 254 | `SSM.SessionRestored` | Session restored |
| 255 | `SSM.SessionTokenRefreshed` | Session token refreshed |
| 256 | `SSM.SecretGenerated` | New secret generated |
| 257 | `SSM.SecretRotated` | Secret rotated |
| 258 | `SSM.SecretRevoked` | Secret revoked |
| 259 | `SSM.SecretCompromised` | Secret compromised |
| 260 | `SSM.SecretDestroyed` | Secret destroyed |
| 261 | `SSM.SecretAccessDenied` | Secret access denied |

---

### 3.4 EAS — Evidence & Audit Service

**Source:** `Bible/04-Execution/Security/Audit/000-EAS.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 262 | Interface | `EvidenceRecord` | Evidence record structure |
| 263 | Interface | `EvidenceQuery` | Evidence query interface |
| 264 | Interface | `ChainVerificationResult` | Chain verification result |

#### EAS Events

| # | Event | Description |
|---|-------|-------------|
| 265 | `EAS.EvidenceSealed` | Evidence record sealed |
| 266 | `EAS.ChainExtended` | Merkle-DAG chain extended |
| 267 | `EAS.ChainVerified` | Chain verification completed |
| 268 | `EAS.RetentionApplied` | Evidence archived per retention |
| 269 | `EAS.IntegrityAlert` | Chain integrity check fails |
| 270 | `EAS.BulkExportInitiated` | Bulk evidence export begins |
| 271 | `EAS.EvidenceArchived` | Evidence archived to cold storage |

---

### 3.5 CSP — Cryptography Service Provider

**Source:** `Bible/04-Execution/Security/Crypto/000-CSP.md`, `Bible/06-Services/Cryptography/000-CSP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 272 | Interface | `SigningRequest` | N/A | CSP signing request |
| 273 | Interface | `SigningResult` | N/A | CSP signing result |
| 274 | Interface | `VerificationRequest` | N/A | CSP verification request |
| 275 | Interface | `VerificationResult` | N/A | CSP verification result |
| 276 | RPC (ACF) | CSP operations | mTLS | All cryptographic operations via ACF |

---

### 3.6 TLM — Trust Level Manager

**Source:** `Bible/04-Execution/Security/Trust/000-TLM.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 277 | Interface | `TrustScore` | Trust score model |

---

### 3.7 Policy System

**Source:** `Bible/04-Execution/Security/Policy-System/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 278 | Interface | `Policy` | 000-PS.md | Policy definition interface |
| 279 | Interface | `ValidationReport` | 002-PVE.md | Policy validation report |

---

### 3.8 Risk Engine

**Source:** `Bible/04-Execution/Security/Risk/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 280 | Interface | `RiskScore` | 000-RE.md | Risk score model |
| 281 | Interface | `AREAttribution` | 002-ARE.md | Advanced risk engine attribution |

---

### 3.9 Execution Auth Pipeline

**Source:** `Bible/04-Execution/Security/Execution-Auth/000-EAS.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 282 | Interface | `PipelineContext` | Verification pipeline context |

---

### 3.10 Sandbox / Isolation

**Source:** `Bible/04-Execution/Security/Sandbox/000-Isolation.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 283 | Interface | `SandboxLimits` | Sandbox resource limits |

---

### 3.11 IDS — Identity Provenance

**Source:** `Bible/04-Execution/Security/IDS/005-Provenance.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 284 | Interface | `ProvenanceChain` | Identity provenance chain |

---

## 4. Institutions

### 4.1 WCS — Worker Communication Service

**Source:** `Bible/03-Institutions/Workers/004-WCS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 285 | RPC | `sendMessage(sender_id, target_id, message_type, payload)` | Capability-based | Send message from one Worker to another |
| 286 | RPC | `broadcastMessage(sender_id, mission_id, message_type, payload)` | Capability-based | Broadcast message to all Workers in mission |
| 287 | RPC | `publishMessage(sender_id, topic, payload)` | Capability-based | Publish message to topic |
| 288 | RPC | `sendMessageWithResponse(...)` | Capability-based | Send message and wait for response |
| 289 | Interface | `MessageChannel` | N/A | All communication patterns implement this |
| 290 | Message | `WorkerMessage` | N/A | message_id, sender_id, target_id, message_type, payload, ttl |

#### WCS Events

| # | Event | Description |
|---|-------|-------------|
| 291 | `WCS.MessageSent` | Worker sends a message |
| 292 | `WCS.MessageDelivered` | Message reaches target |
| 293 | `WCS.MessageFailed` | Message delivery fails |
| 294 | `WCS.MessageExpired` | Message TTL exceeded |
| 295 | `WCS.MessageDropped` | Queue overflow message dropped |
| 296 | `WCS.MessageAuthorizationDenied` | Cross-scope message denied |

---

### 4.2 WSS — Worker Security Service

**Source:** `Bible/03-Institutions/Workers/003-WSS.md`

| # | Event | Description |
|---|-------|-------------|
| 297 | `WSS.CommunicationSpoofAttempt` | Worker attempts to spoof another Worker's identity |

---

### 4.3 Playbook Manager

**Source:** `Bible/03-Institutions/Workers/005-Playbook-Manager.md`

| # | Event | Description |
|---|-------|-------------|
| 298 | `Playbook.Created` | Playbook created |
| 299 | `Playbook.Activated` | Playbook activated |
| 300 | `Playbook.Completed` | Playbook completed |
| 301 | `Playbook.Failed` | Playbook execution failed |
| 302 | `Playbook.StepCompleted` | Playbook step completed |

---

### 4.4 OIS — Organization Interaction Service

**Source:** `Bible/03-Institutions/Organizations/006-OIS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 303 | Interface | `InteractionChannel` | N/A | All communication patterns implement this |
| 304 | ACF Topic | `org.research.findings` | ACF | Cross-Organization research findings subscription |
| 305 | ACF Topic | Org-wide broadcast topic | ACF | Cross-Organization broadcast |

---

## 5. Runtime

### 5.1 Execution Runtime SDK

**Source:** `Bible/04-Execution/Runtime/001-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 306 | Interface | `ExecutionProvider` | Execution token | Interface all execution providers implement |
| 307 | Method | `providerId()` | N/A | Returns provider identity |
| 308 | Method | `providerVersion()` | N/A | Returns provider version |
| 309 | Method | `supportedActionTypes()` | N/A | Returns supported action types |
| 310 | Method | `capabilityDeclaration()` | N/A | Returns capability declaration |
| 311 | Method | `initialize(config)` | N/A | Initialize provider with configuration |
| 312 | Method | `health()` | N/A | Returns provider health status |
| 313 | Method | `shutdown()` | N/A | Graceful shutdown |
| 314 | Method | `execute(context)` | VerificationToken | Execute an action (core contract) |
| 315 | Method | `executeStream(context)` | VerificationToken | Streaming execution |

#### Runtime Messages / Types

| # | Type | Name | Description |
|---|------|------|-------------|
| 316 | Message | `ExecutionContext` | execution_id, token, action, capability_bounds, autonomy_level, parent_entity_id, deadline |
| 317 | Message | `ExecutionResult` | execution_id, status, output, metrics, error, events |
| 318 | Stream Chunk | `ExecutionChunk` | sequence, data, progress, is_final, metrics |

#### Runtime Events

| # | Event | Description |
|---|-------|-------------|
| 319 | `Runtime.ProviderRegistered` | Provider registered with Runtime Manager |
| 320 | `Runtime.ProviderHealthChanged` | Provider health status changes |
| 321 | `Runtime.ProviderExecutionStarted` | Provider execution starts |
| 322 | `Runtime.ProviderResourceWarning` | Provider resource warning |
| 323 | `Runtime.ProviderExecutionCompleted` | Provider execution completed |
| 324 | `Runtime.ProviderExecutionFailed` | Provider execution failed |
| 325 | `Runtime.ProviderBoundsExceeded` | Provider bounds exceeded |
| 326 | `Runtime.ProviderShutdown` | Provider shutdown |

---

### 5.2 Ollama Integration

**Source:** `Bible/04-Execution/Runtime/004-Ollama.md`

| # | Type | Endpoint | Auth | Description |
|---|------|----------|------|-------------|
| 327 | REST | `POST {endpoint}/api/generate` | Network-bound (localhost/private) | Ollama model generation endpoint |
| 328 | REST | `POST {endpoint}/api/chat` | Network-bound (localhost/private) | Ollama chat endpoint |

---

### 5.3 Runtime SDK (Interface Layer)

**Source:** `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 329 | Interface | `RuntimeProvider` | mTLS | Interface for runtime execution providers |
| 330 | Method | `createSession(genome, allocation)` | Execution token | Create Worker session |
| 331 | Method | `startSession(sessionId)` | Execution token | Start session |
| 332 | Method | `pauseSession(sessionId)` | Execution token | Pause session |
| 333 | Method | `resumeSession(sessionId)` | Execution token | Resume session |
| 334 | Method | `terminateSession(sessionId)` | Execution token | Terminate session |
| 335 | Method | `invokeCapability(sessionId, capability, input)` | Execution token | Execute capability |
| 336 | Method | `cancelInvocation(sessionId, invocationId)` | Execution token | Cancel invocation |
| 337 | Method | `getSessionStatus(sessionId)` | Execution token | Query session state |
| 338 | Method | `streamMetrics(sessionId)` | Execution token | Subscribe to metrics |
| 339 | Method | `healthCheck()` | N/A | Report provider health |
| 340 | Method | `reportUsage(sessionId)` | Execution token | Report resource usage |

#### ACF Endpoints

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 341 | `acf://runtime-provider-id/control` | ACF | Runtime provider control endpoint |
| 342 | `acf://runtime-provider-id/metrics` | ACF | Runtime provider metrics endpoint |
| 343 | `acf://runtime-provider-id/events` | ACF | Runtime provider events endpoint |

#### Runtime SDK Events

| # | Event | Description |
|---|-------|-------------|
| 344 | `SDK.RuntimeSessionCreated` | Runtime session created |
| 345 | `SDK.RuntimeSessionStarted` | Session transitions to Running |
| 346 | `SDK.RuntimeSessionPaused` | Session paused |
| 347 | `SDK.RuntimeSessionTerminated` | Session terminates |
| 348 | `SDK.RuntimeInvocationCompleted` | Capability invocation finishes |
| 349 | `SDK.RuntimeHealthChanged` | Provider health changes |
| 350 | `SDK.RuntimeUsageReported` | Resource usage reported |

---

### 5.4 Audit SDK

**Source:** `Bible/08-Interfaces/SDK/001-Audit-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 351 | `queryEvents(filter)` | audit scope | Query Events by filter criteria |
| 352 | `getEventById(eventId)` | audit scope | Retrieve single Event |
| 353 | `streamEvents(filter)` | audit scope | Subscribe to Event stream |
| 354 | `verifyChain(eventId)` | audit scope | Verify Event chain integrity |
| 355 | `verifyIntegrity(eventRange)` | audit scope | Verify Event range integrity |
| 356 | `computeHash(eventId)` | audit scope | Compute cryptographic hash |
| 357 | `analyzePattern(filter, pattern)` | audit scope | Detect patterns across Events |
| 358 | `computeAggregation(filter, metric)` | audit scope | Aggregate metrics |
| 359 | `detectAnomaly(filter, baseline)` | audit scope | Detect anomalous patterns |
| 360 | `checkCompliance(filter, standard)` | audit scope | Check compliance |

---

## 6. Domains

### 6.1 Trading

**Source:** `Bible/07-Domains/Trading/000-Overview.md`

| # | Event | Description |
|---|-------|-------------|
| 361 | `Trading.OrderPlaced` | Order submitted to exchange |

---

### 6.2 Security Domain

**Source:** `Bible/07-Domains/Security/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 362 | RPC | `monitor_endpoints` | Security domain worker capability — monitor endpoints |
| 363 | RPC | `analyze_network` | Security domain worker capability — analyze network traffic |
| 364 | RPC | `detect_intrusion` | Security domain worker capability — detect intrusion |
| 365 | RPC | `alert_triage` | Security domain worker capability — triage alerts |

---

## 7. Federation

### 7.1 AIP — Agent Interoperability Protocol

**Source:** `Bible/06-Services/Federation/001-AIP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 366 | `connectToRemoteAgent(remote_session_id, instance_id)` | mTLS + identity | Initiate cross-instance session |
| 367 | `sendAgentMessage(session_id, message)` | mTLS + identity | Send message to remote session |
| 368 | `disconnectAgent(session_id)` | mTLS | Terminate cross-instance session |
| 369 | `getAgentStatus(session_id)` | mTLS | Check remote session status |

#### AIP Events

| # | Event | Description |
|---|-------|-------------|
| 370 | `AIP.AgentConnected` | Remote session connected |
| 371 | `AIP.AgentDisconnected` | Remote session disconnected |
| 372 | `AIP.MessageSent` | Message transmitted |
| 373 | `AIP.MessageReceived` | Message received |
| 374 | `AIP.ConnectionFailed` | Connection attempt failed |

---

### 7.2 SXP — Security Exchange Protocol

**Source:** `Bible/06-Services/Federation/007-SXP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 375 | `shareThreat(threat_data, severity)` | mTLS + signature | Share threat intelligence |
| 376 | `subscribeThreats(filter, callback_endpoint)` | mTLS | Subscribe to threat feed |
| 377 | `acknowledgeThreat(threat_id, action_taken)` | mTLS | Acknowledge receipt of threat |
| 378 | `escalateThreat(threat_id, escalation_reason)` | Security Council | Request coordinated response |
| 379 | `getThreatStatus(threat_id)` | mTLS | Query threat resolution status |

#### SXP Events

| # | Event | Description |
|---|-------|-------------|
| 380 | `SXP.ThreatShared` | Threat intelligence shared |
| 381 | `SXP.ThreatAcknowledged` | Receipt acknowledged |
| 382 | `SXP.ThreatEscalated` | Threat escalated |
| 383 | `SXP.ThreatResolved` | Threat resolved |
| 384 | `SXP.SubscriptionCreated` | Threat feed subscription |

---

## 8. Governance

| # | Type | Source | Description |
|---|------|--------|-------------|
| 385 | Event | `Bible/01-Governance/001-CLS.md` | CLS constitutional amendment lifecycle events |
| 386 | Event | `Bible/01-Governance/002-DGP.md` | DGP decision assessed events |
| 387 | Event | `Bible/01-Governance/003-CRP.md` | CRP constitutional review proposal events |
| 388 | RPC (ACF) | `Bible/01-Governance/004-CKR.md` | CKR constitutional knowledge registry query interface |
| 389 | Event | `Bible/01-Governance/004-CKR.md` | CKR knowledge registry lifecycle events |
| 390 | Event | `Bible/01-Governance/005-ADG.md` | ADG architecture decision events |
| 391 | Event | `Bible/01-Governance/006-AKM.md` | AKM knowledge management lifecycle events |

---

## 9. Cross-Cutting

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 392 | Interface | `AuthMethod` | `00-Foundations/002-Design-DNA.md` | Interface for implementing new authentication methods |
| 393 | Event | `Lifecycle.EntityArchived` | `00-Foundations/008-Object-Lifecycle.md` | Entity archived event |
| 394 | Schema | Canonical API Envelope | `08-Interfaces/API/000-Specifications.md` | Standard envelope: api_version, message_id, correlation_id, timestamp, source_entity_id, target_entity_id, auth_token, payload |
| 395 | Schema | Error Response Schema | `08-Interfaces/API/000-Specifications.md` | Standard error: code, message, details, correlation_id |

#### Framework API Events

| # | Event | Description |
|---|-------|-------------|
| 396 | `API.ContractPublished` | New API contract registered |
| 397 | `API.ContractDeprecated` | API version deprecated |
| 398 | `API.RequestProcessed` | API request completes |
| 399 | `API.RateLimitExceeded` | Rate limit exceeded |
| 400 | `API.SchemaValidationFailed` | Schema validation failed |

---

## 10. Appendix: Schema Index

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
