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
10. [Appendix: Event Index](#10-appendix-event-index)

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
| 8 | `PSAP.HealthCheck` | mTLS | Health check ping |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 9 | `PSAP.HeartbeatReceived` | Heartbeat received from service |
| 10 | `PSAP.ServiceRegistered` | Service registered |
| 11 | `PSAP.ServiceDeregistered` | Service deregistered |
| 12 | `PSAP.ServiceHealthChanged` | Service health status changed |

---

### 1.2 EVS — Event Store

**Source:** `Bible/05-Platform/004-EVS.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 13 | `appendEvent(stream_id, event_type, data, metadata)` | ACF token | Append event to stream |
| 14 | `readStream(stream_id, from_version?, to_version?)` | ACF token | Read events from stream |
| 15 | `readStreamByTime(stream_id, from_time, to_time)` | ACF token | Read events by time range |
| 16 | `readEventByVersion(stream_id, version)` | ACF token | Read specific event version |
| 17 | `subscribeStream(stream_id, subscriber)` | ACF token | Subscribe to event stream |
| 18 | `getEventCount(stream_id)` | ACF token | Get event count |
| 19 | `getStreamInfo(stream_id)` | ACF token | Get stream info |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 20 | `EVS.EventAppended` | Event written to stream |
| 21 | `EVS.StreamCreated` | Event stream initialized |
| 22 | `EVS.SnapshotCreated` | Snapshot taken |
| 23 | `EVS.SubscriptionActivated` | Subscriber subscribed to stream |
| 24 | `EVS.ReadReplicaAdded` | Read replica came online |

---

### 1.3 EPG — Event Processing Graph

**Source:** `Bible/05-Platform/006-EPG.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 25 | Stream | Event Processing Graph (EPG) | ACF-level | DAG-based event stream processing (filter, transform, enrich, aggregate, route) |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 26 | `EPG.GraphDefined` | New processing graph defined |
| 27 | `EPG.GraphDeployed` | Processing graph deployed |
| 28 | `EPG.GraphUndeployed` | Processing graph undeployed |
| 29 | `EPG.NodeProcessed` | Graph node completed processing |
| 30 | `EPG.PipelineStarted` | Pipeline execution started |
| 31 | `EPG.PipelineCompleted` | Pipeline execution completed |
| 32 | `EPG.PipelineFailed` | Pipeline execution failed |

---

### 1.4 EIP — External Integration Protocol

**Source:** `Bible/05-Platform/007-EIP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 33 | Interface | `Connector` | N/A | All EIP connectors implement this interface |
| 34 | REST/gRPC/AMQP/MQTT | External Integration Protocol | mTLS (varies) | Protocol for webhook, Kafka, MQTT, AMQP, REST, gRPC connectors |

#### Messages

| # | Message | Description |
|---|---------|-------------|
| 35 | `ConnectorConfig` | Protocol, endpoint, format, authentication config |

---

### 1.5 CP — Credential Provider

**Source:** `Bible/05-Platform/012-CP.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 36 | Interface | `Credential` | All credential types implement this |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 37 | `CP.CredentialIssued` | Credential generated |

---

### 1.6 Graph Framework

**Source:** `Bible/05-Platform/013-Graph-Framework.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 38 | Interface | `GraphStore` | N/A | All graph storage backends implement this |
| 39 | RPC (ACF) | Graph Framework operations | ACF-level | Graph queries via ACF |

---

### 1.7 LMS — Lifecycle Management Service

**Source:** `Bible/05-Platform/000-LMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 40 | RPC (ACF) | LMS transition requests | ACF token | Entity lifecycle state transitions via ACF |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 41 | `LMS.EntityCreated` | Entity created |
| 42 | `LMS.EntityStateChanged` | Entity state transitioned |
| 43 | `LMS.EntityCompleted` | Entity lifecycle completed |
| 44 | `LMS.EntityArchived` | Entity archived |
| 45 | `LMS.TransitionRejected` | State transition rejected |

---

## 2. Core Engines

### 2.1 Academy — Knowledge Management

**Source:** `Bible/02-Core/Academy/016-Knowledge-API.md`

#### RPC Methods (via ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 46 | `academy.knowledge.create` | `knowledge.propose` | Propose a new knowledge artifact |
| 47 | `academy.knowledge.validate` | `knowledge.validate` | Trigger validation of knowledge artifact |
| 48 | `academy.knowledge.accept` | `knowledge.accept` | Accept validated knowledge into Registry |
| 49 | `academy.knowledge.query` | `knowledge.query` | Query knowledge artifacts by graph traversal |
| 50 | `academy.knowledge.search` | `knowledge.query` | Full-text, semantic, or faceted search |
| 51 | `academy.knowledge.get` | `knowledge.query` | Retrieve specific knowledge artifact by ID |
| 52 | `academy.knowledge.provenance` | `knowledge.query` | Get full provenance chain for artifact |
| 53 | `academy.knowledge.list` | `knowledge.query` | List knowledge artifacts with filters |
| 54 | `academy.knowledge.deprecate` | `knowledge.deprecate` | Deprecate a knowledge artifact |
| 55 | `academy.knowledge.compose` | `knowledge.compose.{method}` | Request KCE knowledge composition |
| 56 | `academy.knowledge.execute` | `knowledge.execute.{type}` | Request KEE knowledge execution |

#### Pub-Sub (ACF)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 57 | `academy.knowledge.subscribe` | `knowledge.subscribe` | Subscribe to knowledge lifecycle events |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 58 | `API.RequestReceived` | API received a request |
| 59 | `API.RequestCompleted` | API completed processing |
| 60 | `API.RequestFailed` | API encountered an error |
| 61 | `API.RateLimitExceeded` | Rate limit exceeded |
| 62 | `API.SubscriptionCreated` | Subscription created |
| 63 | `API.SubscriptionRemoved` | Subscription removed |

---

### 2.2 Academy — Knowledge Search (REST Gateway)

**Source:** `Bible/02-Core/Academy/010-Knowledge-Search.md`

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 64 | `GET /search?q=...&fields=...&operator=...` | JWT | Full-text knowledge search |
| 65 | `GET /search?q=...&type=semantic&top_k=...` | JWT | Semantic knowledge search |
| 66 | `GET /search?type=graph&start_node_id=...&edge_types=...&max_depth=...` | JWT | Graph-based knowledge search |
| 67 | `GET /search?type=operational&organization_id=...&tags=...&confidence_min=...` | JWT | Faceted/operational knowledge search |

---

### 2.3 Academy — KMS Query Interface

**Source:** `Bible/02-Core/Academy/002-KMS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 68 | RPC (ACF) | KMS query interface | ACF-level | Knowledge management storage and retrieval queries |

---

### 2.4 Academy — Knowledge SDK Provider Interface

**Source:** `Bible/02-Core/Academy/015-Knowledge-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 69 | `authenticate(entity_id, credentials)` | ACF token | Authenticate with ATS and obtain session token |
| 70 | `setIdentity(identity)` | ACF token | Set identity for subsequent operations |
| 71 | `getCurrentEntity()` | ACF token | Returns authenticated entity info |
| 72 | `hasCapability(capability)` | ACF token | Check if entity has a specific capability |
| 73 | `search(query, options)` | ACF token | Full-text and semantic search |
| 74 | `getKnowledge(id)` | ACF token | Retrieve artifact by ID |
| 75 | `listKnowledge(filters)` | ACF token | List artifacts matching filters |
| 76 | `getProvenance(id, options)` | ACF token | Get provenance chain |
| 77 | `queryGraph(query)` | ACF token | Graph traversal query |
| 78 | `subscribe(topic, callback)` | ACF token | Subscribe to knowledge events |
| 79 | `unsubscribe(subscriptionId)` | ACF token | Unsubscribe from events |
| 80 | `onKnowledgeAccepted(callback)` | ACF token | Convenience subscription for accepted events |
| 81 | `onKnowledgeDeprecated(callback)` | ACF token | Convenience subscription for deprecation events |
| 82 | `proposeKnowledge(artifact)` | ACF token | Submit knowledge for validation |
| 83 | `getProposalStatus(proposalId)` | ACF token | Check proposal status |
| 84 | `withdrawProposal(proposalId)` | ACF token | Withdraw a pending proposal |
| 85 | `resubmitKnowledge(proposalId, updatedArtifact)` | ACF token | Resubmit with revisions |
| 86 | `composeUnion(artifactIds)` | ACF token | Union composition |
| 87 | `composeIntersection(artifactIds)` | ACF token | Intersection composition |
| 88 | `composeAnalogy(sourceId, targetDomain)` | ACF token | Analogy composition |
| 89 | `composeInduction(artifactIds)` | ACF token | Induction composition |
| 90 | `composeDeduction(principleId, context)` | ACF token | Deduction composition |
| 91 | `getCompositionStatus(requestId)` | ACF token | Check composition request status |
| 92 | `executeKnowledge(knowledgeId, context)` | ACF token | Execute a knowledge artifact |
| 93 | `getExecutionStatus(executionId)` | ACF token | Check execution status |
| 94 | `cancelExecution(executionId)` | ACF token | Cancel a pending execution |
| 95 | `getExecutionResult(executionId)` | ACF token | Get execution result |

#### SDK Events

| # | Event | Description |
|---|-------|-------------|
| 96 | `SDK.Authenticated` | SDK successfully authenticates |
| 97 | `SDK.QueryExecuted` | SDK executes a query |
| 98 | `SDK.KnowledgeProposed` | SDK proposes knowledge |
| 99 | `SDK.EventSubscribed` | SDK subscribes to a topic |
| 100 | `SDK.EventReceived` | SDK receives an event |
| 101 | `SDK.ErrorEncountered` | SDK encounters an error |

---

### 2.5 Sou — Reasoning Engine

**Source:** `Bible/02-Core/Sou/001-Reasoning.md`, `Bible/02-Core/Sou/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 102 | Interface | `Reasoner` | All reasoning methods implement this |
| 103 | Interface | `SouEngine` | Common interface for Planner, Reasoning, Missions, Learning, Knowledge |

#### Events

| # | Event | Description |
|---|-------|-------------|
| 104 | `Sou.ReasoningFailed` | Reasoning encountered an error |

---

### 2.6 DTS — Decision & Trust Scoring

**Source:** `Bible/02-Core/DTS/001-Architecture.md`, `Bible/02-Core/DTS/003-Sim-Engines.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 105 | Interface | `DecisionEvaluator` | Interface for evaluating decisions |
| 106 | Interface | `EvaluationResult` | Interface for evaluation results |
| 107 | Interface | `TrustScorer` | Interface for trust scoring |
| 108 | Interface | `TrustScore` | Interface for trust score data |
| 109 | Interface | `SimEngine` | All simulation engines implement this |

---

### 2.7 ROS — Resource Orchestration

**Source:** `Bible/02-Core/ROS/008-Provider-SDK.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 110 | Interface | `ResourceProvider` | SDK interface that all resource providers must implement |

---

## 3. Security Council

### 3.1 ACF — Anticipatory Communication Fabric

**Source:** `Bible/06-Services/ACF/`

#### 3.1.1 Messaging (`002-Messages.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 111 | `sendMessage(envelope, payload)` | auth_token | Send a message |
| 112 | `sendMessageWithAck(envelope, payload, timeout)` | auth_token | Send with acknowledgement |
| 113 | `receiveMessage(entity_id, timeout?)` | auth_token | Receive a message |
| 114 | `getMessageStatus(message_id)` | auth_token | Get message delivery status |
| 115 | `retryMessage(message_id)` | auth_token | Retry failed message |
| 116 | `deadLetterMessage(message_id, reason)` | auth_token | Move to dead letter queue |
| 117 | `acknowledgeMessage(message_id)` | auth_token | Acknowledge message |
| 118 | `rejectMessage(message_id, reason)` | auth_token | Reject message |

#### 3.1.2 Routing (`003-Routing.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 119 | `defineRoute(target_pattern, endpoints, config)` | Security Council | Define routing rule |
| 120 | `updateRoute(route_id, updates)` | Security Council | Update routing rule |
| 121 | `removeRoute(route_id)` | Security Council | Remove routing rule |
| 122 | `resolveRoute(target, sender?)` | ACF-level | Resolve target to endpoint |
| 123 | `getRoute(route_id)` | ACF-level | Get route entry |
| 124 | `listRoutes(filter?)` | ACF-level | List routing entries |
| 125 | `testRoute(target, message?)` | ACF-level | Test route resolution |

#### 3.1.3 Subscriptions (`004-Subscriptions.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 126 | `subscribe(entity_id, topic_pattern, subscription_type, config)` | ACF-level | Subscribe to topic |
| 127 | `unsubscribe(subscription_id)` | ACF-level | Unsubscribe from topic |
| 128 | `publish(topic, message)` | ACF-level | Publish message to topic |
| 129 | `listSubscriptions(entity_id)` | ACF-level | List subscriptions |
| 130 | `listSubscribers(topic)` | ACF-level | List subscribers of topic |
| 131 | `getSubscriptionStatus(subscription_id)` | ACF-level | Get subscription status |
| 132 | `updateSubscription(subscription_id, updates)` | ACF-level | Update subscription configuration |

#### Canonical ACF Topic Names

| # | Topic Pattern | Description |
|---|--------------|-------------|
| 133 | `academy.knowledge.accepted` | Knowledge accepted events |
| 134 | `academy.knowledge.rejected` | Knowledge rejected events |
| 135 | `academy.knowledge.revised` | Knowledge revised events |
| 136 | `lifecycle.state.changed` | Lifecycle state changes |
| 137 | `lifecycle.entity.created` | Entity created |
| 138 | `lifecycle.entity.completed` | Entity completed |
| 139 | `security.auth.authenticated` | Auth success events |
| 140 | `security.auth.authorized` | Auth authorized events |
| 141 | `security.auth.denied` | Auth denied events |
| 142 | `system.session.created` | Session created |
| 143 | `system.session.destroyed` | Session destroyed |
| 144 | `aios/{domain}/{service}/{instance}/health` | Health check topic for all services |

#### 3.1.4 Streaming (`005-Streaming.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 145 | `createStream(topic, partitions, config)` | ACF-level | Create a stream |
| 146 | `deleteStream(stream_id)` | ACF-level | Delete a stream |
| 147 | `publishToStream(topic, message, partition_key?)` | ACF-level | Publish to stream |
| 148 | `publishToPartition(stream_id, partition_id, message)` | ACF-level | Publish to specific partition |
| 149 | `consumeStream(stream_id, consumer_group, consumer_id)` | ACF-level | Consume from stream |
| 150 | `getStreamPosition(consumer_group, consumer_id, partition_id?)` | ACF-level | Get stream position |
| 151 | `seekStream(consumer_group, consumer_id, position)` | ACF-level | Seek to position |
| 152 | `commitPosition(consumer_group, consumer_id, partition_id, sequence)` | ACF-level | Commit consumer position |
| 153 | `getStreamInfo(stream_id)` | ACF-level | Get stream info |
| 154 | `listStreams(filter?)` | ACF-level | List streams |

#### 3.1.5 Reliability / DLQ (`006-Reliability.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 155 | `configureRetry(topic_pattern, retry_policy)` | Security Council | Configure retry policy |
| 156 | `getRetryStatus(message_id)` | ACF-level | Get retry status |
| 157 | `getDeadLetterMessages(filter?)` | Security Council | List DLQ messages |
| 158 | `replayDeadLetter(dlq_message_id, new_target?)` | Security Council | Replay DLQ message |
| 159 | `replayAllDeadLetter(filter?)` | Security Council | Replay all DLQ messages |
| 160 | `purgeDeadLetter(filter?)` | Security Council | Purge DLQ messages |
| 161 | `getDeadLetterStats()` | Security Council | Get DLQ statistics |
| 162 | `getDeadLetterMessage(dlq_message_id)` | Security Council | Get specific DLQ message |

#### 3.1.6 Distributed / Federation (`007-Distributed.md`)

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 163 | `connectInstance(instance_url, credentials, config)` | mTLS X.509 | Connect to remote ACF instance |
| 164 | `disconnectInstance(bridge_id)` | mTLS | Disconnect remote instance |
| 165 | `syncRoutingTable(bridge_id)` | mTLS | Sync routing tables |
| 166 | `getInstanceStatus(instance_id)` | mTLS | Get remote instance status |
| 167 | `listConnectedInstances()` | mTLS | List all connected instances |
| 168 | `updateBandwidth(bridge_id, bandwidth_bps)` | Security Council | Update bridge bandwidth |
| 169 | `updateExportPolicy(bridge_id, policy)` | Security Council | Update route export policy |

#### ACF Messages

| # | Message | Description |
|---|---------|-------------|
| 170 | `Message` (envelope + payload) | Fundamental unit of communication |
| 171 | `Envelope` | Routing and metadata (version, message_id, sender, target, timestamp, ttl, priority, delivery_mode) |
| 172 | `DeliveryStatus` | Message delivery status tracking |
| 173 | `DeliveryAttempt` | Delivery attempt record |
| 174 | `DeadLetterMessage` | Undeliverable message with failure metadata |
| 175 | `DeliveryFailure` | Delivery failure details |
| 176 | `RetryPolicy` | Retry policy configuration |

#### ACF Events

| # | Event | Source | Description |
|---|-------|--------|-------------|
| 177 | `ACF.MessageSent` | 002-Messages | Sender dispatches message |
| 178 | `ACF.MessageAuthenticated` | 002-Messages | Token verified |
| 179 | `ACF.MessageAuthorized` | 002-Messages | Route permitted |
| 180 | `ACF.MessageQueued` | 002-Messages | Message persisted |
| 181 | `ACF.MessageRouted` | 002-Messages | Target endpoint selected |
| 182 | `ACF.MessageDelivered` | 002-Messages | Message reaches receiver |
| 183 | `ACF.MessageAcknowledged` | 002-Messages | Receiver confirms |
| 184 | `ACF.MessageFailed` | 002-Messages | Permanent delivery failure |
| 185 | `ACF.MessageExpired` | 002-Messages | TTL exceeded |
| 186 | `ACF.RouteDefined` | 003-Routing | Route created |
| 187 | `ACF.RouteUpdated` | 003-Routing | Route modified |
| 188 | `ACF.RouteRemoved` | 003-Routing | Route deleted |
| 189 | `ACF.EndpointUnavailable` | 003-Routing | Endpoint becomes unhealthy |
| 190 | `ACF.EndpointRestored` | 003-Routing | Endpoint becomes healthy |
| 191 | `ACF.RouteUnresolvable` | 003-Routing | No route matches |
| 192 | `ACF.RoutingTableSynced` | 003-Routing | Routing table synchronized |
| 193 | `ACF.SubscriptionCreated` | 004-Subscriptions | Subscription created |
| 194 | `ACF.SubscriptionActivated` | 004-Subscriptions | Subscription activated |
| 195 | `ACF.SubscriptionPaused` | 004-Subscriptions | Subscription paused |
| 196 | `ACF.SubscriptionResumed` | 004-Subscriptions | Subscription resumed |
| 197 | `ACF.SubscriptionUnsubscribed` | 004-Subscriptions | Subscription ended |
| 198 | `ACF.MessagePublished` | 004-Subscriptions | Message published to topic |
| 199 | `ACF.SubscriptionDelivered` | 004-Subscriptions | Message delivered to subscriber |
| 200 | `ACF.BackpressureApplied` | 004-Subscriptions | Slow subscriber throttled |
| 201 | `ACF.FilterEvaluated` | 004-Subscriptions | Filter predicate evaluated |
| 202 | `ACF.StreamCreated` | 005-Streaming | Stream created |
| 203 | `ACF.StreamDeleted` | 005-Streaming | Stream deleted |
| 204 | `ACF.PartitionReassigned` | 005-Streaming | Partition reassigned |
| 205 | `ACF.ConsumerAdded` | 005-Streaming | Consumer joins group |
| 206 | `ACF.ConsumerRemoved` | 005-Streaming | Consumer leaves |
| 207 | `ACF.ConsumerRebalanced` | 005-Streaming | Group rebalanced |
| 208 | `ACF.StreamEnd` | 005-Streaming | Stream reaches end |
| 209 | `ACF.PositionCommitted` | 005-Streaming | Consumer commits position |
| 210 | `ACF.RetryPolicyConfigured` | 006-Reliability | Retry policy set |
| 211 | `ACF.DeliveryAttempted` | 006-Reliability | Delivery attempt made |
| 212 | `ACF.DeliverySucceeded` | 006-Reliability | Delivery succeeds |
| 213 | `ACF.DeliveryFailed` | 006-Reliability | Delivery fails |
| 214 | `ACF.MessageDeadLettered` | 006-Reliability | Message sent to DLQ |
| 215 | `ACF.DLQReplayed` | 006-Reliability | DLQ message replayed |
| 216 | `ACF.DLQPurged` | 006-Reliability | DLQ messages purged |
| 217 | `ACF.ReliabilityThresholdBreached` | 006-Reliability | Reliability target missed |
| 218 | `ACF.DLQReviewed` | 006-Reliability | DLQ review completed |
| 219 | `ACF.InstanceConnected` | 007-Distributed | ACF bridge established |
| 220 | `ACF.InstanceDisconnected` | 007-Distributed | Bridge torn down |
| 221 | `ACF.InstancePartitioned` | 007-Distributed | Network partition detected |
| 222 | `ACF.InstanceReconnected` | 007-Distributed | Partition healed |
| 223 | `ACF.RoutingTableSynced` | 007-Distributed | Routing tables synchronized |
| 224 | `ACF.CrossInstanceMessageSent` | 007-Distributed | Message crosses instance boundary |
| 225 | `ACF.CrossInstanceMessageReceived` | 007-Distributed | Message received from remote |
| 226 | `ACF.HopLimitExceeded` | 007-Distributed | Message exceeds max hops |
| 227 | `ACF.BandwidthExceeded` | 007-Distributed | Bandwidth limit hit |
| 228 | `ACF.ClusterNodeJoined` | 001-Architecture | New node joins ACF cluster |
| 229 | `ACF.ClusterNodeLeft` | 001-Architecture | Node leaves cluster |
| 230 | `ACF.ClusterLeaderElected` | 001-Architecture | New Raft leader elected |
| 231 | `ACF.TopicPartitionCreated` | 001-Architecture | Topic partition created |
| 232 | `ACF.TopicPartitionReassigned` | 001-Architecture | Partition reassigned |

---

### 3.2 AZS — Authorization Services

**Source:** `Bible/04-Execution/Security/AZS/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 233 | Interface | `Permission` | 000-RBAC.md | Permission definition interface |
| 234 | Interface | `ABACPolicy` | 001-ABAC.md | Attribute-based access control policy interface |
| 235 | Interface | `Capability` | 002-Capability.md | Capability token interface |

#### AZS Events

| # | Event | Description |
|---|-------|-------------|
| 236 | `AZS.CapabilityIssued` | Capability created |
| 237 | `AZS.CapabilityPresented` | Capability presented for verification |
| 238 | `AZS.CapabilityVerified` | Capability passes verification |
| 239 | `AZS.CapabilityDenied` | Capability fails verification |
| 240 | `AZS.CapabilityRevoked` | Capability revoked |
| 241 | `AZS.CapabilityExpired` | Capability expired |
| 242 | `AZS.DelegationExtended` | Delegation extended |
| 243 | `AZS.CapabilityConsumed` | One-time capability consumed |

---

### 3.3 SSM — Session & Secret Management

**Source:** `Bible/04-Execution/Security/SSM/000-SSM.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 244 | Interface | `Session` | Session model interface |
| 245 | Interface | `SessionToken` | Session token interface |
| 246 | Interface | `Secret` | Secret model interface |

#### SSM Events

| # | Event | Description |
|---|-------|-------------|
| 247 | `SSM.SessionCreated` | New session created |
| 248 | `SSM.SessionAuthenticated` | Session authenticated |
| 249 | `SSM.SessionTerminated` | Session terminated |
| 250 | `SSM.SessionSuspended` | Session suspended |
| 251 | `SSM.SessionRestored` | Session restored |
| 252 | `SSM.SessionTokenRefreshed` | Session token refreshed |
| 253 | `SSM.SecretGenerated` | New secret generated |
| 254 | `SSM.SecretRotated` | Secret rotated |
| 255 | `SSM.SecretRevoked` | Secret revoked |
| 256 | `SSM.SecretCompromised` | Secret compromised |
| 257 | `SSM.SecretDestroyed` | Secret destroyed |
| 258 | `SSM.SecretAccessDenied` | Secret access denied |

---

### 3.4 EAS — Evidence & Audit Service

**Source:** `Bible/04-Execution/Security/Audit/000-EAS.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 259 | Interface | `EvidenceRecord` | Evidence record structure |
| 260 | Interface | `EvidenceQuery` | Evidence query interface |
| 261 | Interface | `ChainVerificationResult` | Chain verification result |

#### EAS Events

| # | Event | Description |
|---|-------|-------------|
| 262 | `EAS.EvidenceSealed` | Evidence record sealed |
| 263 | `EAS.ChainExtended` | Merkle-DAG chain extended |
| 264 | `EAS.ChainVerified` | Chain verification completed |
| 265 | `EAS.RetentionApplied` | Evidence archived per retention |
| 266 | `EAS.IntegrityAlert` | Chain integrity check fails |
| 267 | `EAS.BulkExportInitiated` | Bulk evidence export begins |
| 268 | `EAS.EvidenceArchived` | Evidence archived to cold storage |

---

### 3.5 CSP — Cryptography Service Provider

**Source:** `Bible/04-Execution/Security/Crypto/000-CSP.md`, `Bible/06-Services/Cryptography/000-CSP.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 269 | Interface | `SigningRequest` | N/A | CSP signing request |
| 270 | Interface | `SigningResult` | N/A | CSP signing result |
| 271 | Interface | `VerificationRequest` | N/A | CSP verification request |
| 272 | Interface | `VerificationResult` | N/A | CSP verification result |
| 273 | RPC (ACF) | CSP operations | mTLS | All cryptographic operations via ACF |

---

### 3.6 TLM — Trust Level Manager

**Source:** `Bible/04-Execution/Security/Trust/000-TLM.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 274 | Interface | `TrustScore` | Trust score model |

---

### 3.7 Policy System

**Source:** `Bible/04-Execution/Security/Policy-System/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 275 | Interface | `Policy` | 000-PS.md | Policy definition interface |
| 276 | Interface | `ValidationReport` | 002-PVE.md | Policy validation report |

---

### 3.8 Risk Engine

**Source:** `Bible/04-Execution/Security/Risk/`

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 277 | Interface | `RiskScore` | 000-RE.md | Risk score model |
| 278 | Interface | `AREAttribution` | 002-ARE.md | Advanced risk engine attribution |

---

### 3.9 Execution Auth Pipeline

**Source:** `Bible/04-Execution/Security/Execution-Auth/000-EAS.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 279 | Interface | `PipelineContext` | Verification pipeline context |

---

### 3.10 Sandbox / Isolation

**Source:** `Bible/04-Execution/Security/Sandbox/000-Isolation.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 280 | Interface | `SandboxLimits` | Sandbox resource limits |

---

### 3.11 IDS — Identity Provenance

**Source:** `Bible/04-Execution/Security/IDS/005-Provenance.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 281 | Interface | `ProvenanceChain` | Identity provenance chain |

---

## 4. Institutions

### 4.1 WCS — Worker Communication Service

**Source:** `Bible/03-Institutions/Workers/004-WCS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 282 | RPC | `sendMessage(sender_id, target_id, message_type, payload)` | Capability-based | Send message from one Worker to another |
| 283 | RPC | `broadcastMessage(sender_id, mission_id, message_type, payload)` | Capability-based | Broadcast message to all Workers in mission |
| 284 | RPC | `publishMessage(sender_id, topic, payload)` | Capability-based | Publish message to topic |
| 285 | RPC | `sendMessageWithResponse(...)` | Capability-based | Send message and wait for response |
| 286 | Interface | `MessageChannel` | N/A | All communication patterns implement this |
| 287 | Message | `WorkerMessage` | N/A | message_id, sender_id, target_id, message_type, payload, ttl |

#### WCS Events

| # | Event | Description |
|---|-------|-------------|
| 288 | `WCS.MessageSent` | Worker sends a message |
| 289 | `WCS.MessageDelivered` | Message reaches target |
| 290 | `WCS.MessageFailed` | Message delivery fails |
| 291 | `WCS.MessageExpired` | Message TTL exceeded |
| 292 | `WCS.MessageDropped` | Queue overflow message dropped |
| 293 | `WCS.MessageAuthorizationDenied` | Cross-scope message denied |

---

### 4.2 WSS — Worker Security Service

**Source:** `Bible/03-Institutions/Workers/003-WSS.md`

| # | Event | Description |
|---|-------|-------------|
| 294 | `WSS.CommunicationSpoofAttempt` | Worker attempts to spoof another Worker's identity |

---

### 4.3 Playbook Manager

**Source:** `Bible/03-Institutions/Workers/005-Playbook-Manager.md`

| # | Event | Description |
|---|-------|-------------|
| 295 | `Playbook.Created` | Playbook created |
| 296 | `Playbook.Activated` | Playbook activated |
| 297 | `Playbook.Completed` | Playbook completed |
| 298 | `Playbook.Failed` | Playbook execution failed |
| 299 | `Playbook.StepCompleted` | Playbook step completed |

---

### 4.4 OIS — Organization Interaction Service

**Source:** `Bible/03-Institutions/Organizations/006-OIS.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 300 | Interface | `InteractionChannel` | N/A | All communication patterns implement this |
| 301 | ACF Topic | `org.research.findings` | ACF | Cross-Organization research findings subscription |
| 302 | ACF Topic | Org-wide broadcast topic | ACF | Cross-Organization broadcast |

---

## 5. Runtime

### 5.1 Execution Runtime SDK

**Source:** `Bible/04-Execution/Runtime/001-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 303 | Interface | `ExecutionProvider` | Execution token | Interface all execution providers implement |
| 304 | Method | `providerId()` | N/A | Returns provider identity |
| 305 | Method | `providerVersion()` | N/A | Returns provider version |
| 306 | Method | `supportedActionTypes()` | N/A | Returns supported action types |
| 307 | Method | `capabilityDeclaration()` | N/A | Returns capability declaration |
| 308 | Method | `initialize(config)` | N/A | Initialize provider with configuration |
| 309 | Method | `health()` | N/A | Returns provider health status |
| 310 | Method | `shutdown()` | N/A | Graceful shutdown |
| 311 | Method | `execute(context)` | VerificationToken | Execute an action (core contract) |
| 312 | Method | `executeStream(context)` | VerificationToken | Streaming execution |

#### Runtime Messages / Types

| # | Type | Name | Description |
|---|------|------|-------------|
| 313 | Message | `ExecutionContext` | execution_id, token, action, capability_bounds, autonomy_level, parent_entity_id, deadline |
| 314 | Message | `ExecutionResult` | execution_id, status, output, metrics, error, events |
| 315 | Stream Chunk | `ExecutionChunk` | sequence, data, progress, is_final, metrics |

#### Runtime Events

| # | Event | Description |
|---|-------|-------------|
| 316 | `Runtime.ProviderRegistered` | Provider registered with Runtime Manager |
| 317 | `Runtime.ProviderHealthChanged` | Provider health status changes |
| 318 | `Runtime.ProviderExecutionStarted` | Provider execution starts |
| 319 | `Runtime.ProviderResourceWarning` | Provider resource warning |
| 320 | `Runtime.ProviderExecutionCompleted` | Provider execution completed |
| 321 | `Runtime.ProviderExecutionFailed` | Provider execution failed |
| 322 | `Runtime.ProviderBoundsExceeded` | Provider bounds exceeded |
| 323 | `Runtime.ProviderShutdown` | Provider shutdown |

---

### 5.2 Ollama Integration

**Source:** `Bible/04-Execution/Runtime/004-Ollama.md`

| # | Type | Endpoint | Auth | Description |
|---|------|----------|------|-------------|
| 324 | REST | `POST {endpoint}/api/generate` | Network-bound (localhost/private) | Ollama model generation endpoint |
| 325 | REST | `POST {endpoint}/api/chat` | Network-bound (localhost/private) | Ollama chat endpoint |

---

### 5.3 Runtime SDK (Interface Layer)

**Source:** `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`

| # | Type | Name | Auth | Description |
|---|------|------|------|-------------|
| 326 | Interface | `RuntimeProvider` | mTLS | Interface for runtime execution providers |
| 327 | Method | `createSession(genome, allocation)` | Execution token | Create Worker session |
| 328 | Method | `startSession(sessionId)` | Execution token | Start session |
| 329 | Method | `pauseSession(sessionId)` | Execution token | Pause session |
| 330 | Method | `resumeSession(sessionId)` | Execution token | Resume session |
| 331 | Method | `terminateSession(sessionId)` | Execution token | Terminate session |
| 332 | Method | `invokeCapability(sessionId, capability, input)` | Execution token | Execute capability |
| 333 | Method | `cancelInvocation(sessionId, invocationId)` | Execution token | Cancel invocation |
| 334 | Method | `getSessionStatus(sessionId)` | Execution token | Query session state |
| 335 | Method | `streamMetrics(sessionId)` | Execution token | Subscribe to metrics |
| 336 | Method | `healthCheck()` | N/A | Report provider health |
| 337 | Method | `reportUsage(sessionId)` | Execution token | Report resource usage |

#### ACF Endpoints

| # | Endpoint | Auth | Description |
|---|----------|------|-------------|
| 338 | `acf://runtime-provider-id/control` | ACF | Runtime provider control endpoint |
| 339 | `acf://runtime-provider-id/metrics` | ACF | Runtime provider metrics endpoint |
| 340 | `acf://runtime-provider-id/events` | ACF | Runtime provider events endpoint |

#### Runtime SDK Events

| # | Event | Description |
|---|-------|-------------|
| 341 | `SDK.RuntimeSessionCreated` | Runtime session created |
| 342 | `SDK.RuntimeSessionStarted` | Session transitions to Running |
| 343 | `SDK.RuntimeSessionPaused` | Session paused |
| 344 | `SDK.RuntimeSessionTerminated` | Session terminates |
| 345 | `SDK.RuntimeInvocationCompleted` | Capability invocation finishes |
| 346 | `SDK.RuntimeHealthChanged` | Provider health changes |
| 347 | `SDK.RuntimeUsageReported` | Resource usage reported |

---

### 5.4 Audit SDK

**Source:** `Bible/08-Interfaces/SDK/001-Audit-SDK.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 348 | `queryEvents(filter)` | audit scope | Query Events by filter criteria |
| 349 | `getEventById(eventId)` | audit scope | Retrieve single Event |
| 350 | `streamEvents(filter)` | audit scope | Subscribe to Event stream |
| 351 | `verifyChain(eventId)` | audit scope | Verify Event chain integrity |
| 352 | `verifyIntegrity(eventRange)` | audit scope | Verify Event range integrity |
| 353 | `computeHash(eventId)` | audit scope | Compute cryptographic hash |
| 354 | `analyzePattern(filter, pattern)` | audit scope | Detect patterns across Events |
| 355 | `computeAggregation(filter, metric)` | audit scope | Aggregate metrics |
| 356 | `detectAnomaly(filter, baseline)` | audit scope | Detect anomalous patterns |
| 357 | `checkCompliance(filter, standard)` | audit scope | Check compliance |

---

## 6. Domains

### 6.1 Trading

**Source:** `Bible/07-Domains/Trading/000-Overview.md`

| # | Event | Description |
|---|-------|-------------|
| 358 | `Trading.OrderPlaced` | Order submitted to exchange |

---

### 6.2 Security Domain

**Source:** `Bible/07-Domains/Security/000-Overview.md`

| # | Type | Name | Description |
|---|------|------|-------------|
| 359 | RPC | `monitor_endpoints` | Security domain worker capability — monitor endpoints |
| 360 | RPC | `analyze_network` | Security domain worker capability — analyze network traffic |
| 361 | RPC | `detect_intrusion` | Security domain worker capability — detect intrusion |
| 362 | RPC | `alert_triage` | Security domain worker capability — triage alerts |

---

## 7. Federation

### 7.1 AIP — Agent Interoperability Protocol

**Source:** `Bible/06-Services/Federation/001-AIP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 363 | `connectToRemoteAgent(remote_session_id, instance_id)` | mTLS + identity | Initiate cross-instance session |
| 364 | `sendAgentMessage(session_id, message)` | mTLS + identity | Send message to remote session |
| 365 | `disconnectAgent(session_id)` | mTLS | Terminate cross-instance session |
| 366 | `getAgentStatus(session_id)` | mTLS | Check remote session status |

#### AIP Events

| # | Event | Description |
|---|-------|-------------|
| 367 | `AIP.AgentConnected` | Remote session connected |
| 368 | `AIP.AgentDisconnected` | Remote session disconnected |
| 369 | `AIP.MessageSent` | Message transmitted |
| 370 | `AIP.MessageReceived` | Message received |
| 371 | `AIP.ConnectionFailed` | Connection attempt failed |

---

### 7.2 SXP — Security Exchange Protocol

**Source:** `Bible/06-Services/Federation/007-SXP.md`

| # | Method | Auth | Description |
|---|--------|------|-------------|
| 372 | `shareThreat(threat_data, severity)` | mTLS + signature | Share threat intelligence |
| 373 | `subscribeThreats(filter, callback_endpoint)` | mTLS | Subscribe to threat feed |
| 374 | `acknowledgeThreat(threat_id, action_taken)` | mTLS | Acknowledge receipt of threat |
| 375 | `escalateThreat(threat_id, escalation_reason)` | Security Council | Request coordinated response |
| 376 | `getThreatStatus(threat_id)` | mTLS | Query threat resolution status |

#### SXP Events

| # | Event | Description |
|---|-------|-------------|
| 377 | `SXP.ThreatShared` | Threat intelligence shared |
| 378 | `SXP.ThreatAcknowledged` | Receipt acknowledged |
| 379 | `SXP.ThreatEscalated` | Threat escalated |
| 380 | `SXP.ThreatResolved` | Threat resolved |
| 381 | `SXP.SubscriptionCreated` | Threat feed subscription |

---

## 8. Governance

| # | Type | Source | Description |
|---|------|--------|-------------|
| 382 | Event | `Bible/01-Governance/001-CLS.md` | CLS constitutional amendment lifecycle events |
| 383 | Event | `Bible/01-Governance/002-DGP.md` | DGP decision assessed events |
| 384 | Event | `Bible/01-Governance/003-CRP.md` | CRP constitutional review proposal events |
| 385 | RPC (ACF) | `Bible/01-Governance/004-CKR.md` | CKR constitutional knowledge registry query interface |
| 386 | Event | `Bible/01-Governance/004-CKR.md` | CKR knowledge registry lifecycle events |
| 387 | Event | `Bible/01-Governance/005-ADG.md` | ADG architecture decision events |
| 388 | Event | `Bible/01-Governance/006-AKM.md` | AKM knowledge management lifecycle events |

---

## 9. Cross-Cutting

| # | Type | Name | Source | Description |
|---|------|------|--------|-------------|
| 389 | Interface | `AuthMethod` | `00-Foundations/002-Design-DNA.md` | Interface for implementing new authentication methods |
| 390 | Event | `Lifecycle.EntityArchived` | `00-Foundations/008-Object-Lifecycle.md` | Entity archived event |
| 391 | Schema | Canonical API Envelope | `08-Interfaces/API/000-Specifications.md` | Standard envelope: api_version, message_id, correlation_id, timestamp, source_entity_id, target_entity_id, auth_token, payload |
| 392 | Schema | Error Response Schema | `08-Interfaces/API/000-Specifications.md` | Standard error: code, message, details, correlation_id |

#### Framework API Events

| # | Event | Description |
|---|-------|-------------|
| 393 | `API.ContractPublished` | New API contract registered |
| 394 | `API.ContractDeprecated` | API version deprecated |
| 395 | `API.RequestProcessed` | API request completes |
| 396 | `API.RateLimitExceeded` | Rate limit exceeded |
| 397 | `API.SchemaValidationFailed` | Schema validation failed |

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
