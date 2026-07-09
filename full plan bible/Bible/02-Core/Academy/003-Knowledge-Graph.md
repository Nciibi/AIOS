# AIOS Bible — Core
## Academy — 003: Knowledge Graph

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-003 |
| Source Laws | Law 4 — Evidence |
| Source Physics | Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge Graph (KG) models the relationships between knowledge artifacts, entities, events, and concepts as a directed graph. While the KMS (002) stores individual artifacts, the Knowledge Graph captures how they connect — which knowledge derives from which events, which artifacts support or contradict each other, and how concepts relate across domains.

## Graph Structure

### Node Types

| Node Type | Description | Identifier | Properties |
|-----------|-------------|------------|------------|
| `KnowledgeArtifact` | A knowledge artifact (from KMS) | UUID (artifact_id) | type, version, status, timestamp |
| `Entity` | An AIOS entity that produced or consumed knowledge | UUID (entity_id) | entity_type, autonomy_level, organization_id |
| `Event` | A source Event from the Event Store | UUID (event_id) | event_type, timestamp, source_entity_id |
| `Concept` | An abstract concept or topic | String (normalized name) | domain, description, aliases |
| `Organization` | An Organization that scopes knowledge | UUID (org_id) | name, type |

### Edge Types

| Edge Type | From | To | Description | Weighted? |
|-----------|------|----|-------------|-----------|
| `derived_from` | KnowledgeArtifact | Event | Knowledge is derived from this Event | No |
| `derived_from` | KnowledgeArtifact | KnowledgeArtifact | Knowledge is derived from another artifact | No |
| `supports` | KnowledgeArtifact | KnowledgeArtifact | Artifact supports the target's claim | Yes (0.0–1.0) |
| `contradicts` | KnowledgeArtifact | KnowledgeArtifact | Artifact contradicts the target's claim | Yes (0.0–1.0) |
| `supersedes` | KnowledgeArtifact | KnowledgeArtifact | This artifact supersedes the target | No |
| `references` | KnowledgeArtifact | Entity | Artifact references an entity | No |
| `references` | KnowledgeArtifact | Concept | Artifact references a concept | No |
| `references` | Event | Entity | Event references an entity | No |
| `categorizes` | KnowledgeArtifact | Concept | Artifact is categorized under a concept | No |
| `produced_by` | Event | Entity | Event was produced by an entity | No |
| `consumed_by` | KnowledgeArtifact | Entity | Knowledge was consumed by an entity | Yes (count) |

## Example Subgraph

```
┌──────────┐    produced_by    ┌──────────┐
│  Event   │──────────────────▶│  Entity  │
│ E-001    │                   │  AG-042  │
└────┬─────┘                   └──────────┘
     │                                ▲
     │ derived_from                   │ consumed_by
     ▼                                │
┌──────────┐    supports    ┌──────────┐
│  Artifact│──────────────▶│  Artifact│
│  A-001   │               │  A-002   │
│  (Oper)  │               │  (Domain)│
└────┬─────┘               └──────────┘
     │                           │
     │ categorizes               │ references
     ▼                           ▼
┌──────────┐              ┌──────────┐
│ Concept  │              │ Concept  │
│ "Auth"   │              │ "JWT"    │
└──────────┘              └──────────┘
```

## Graph Operations

### Traverse

Walk the graph along specified edge types from a starting node.

| Parameter | Description |
|-----------|-------------|
| `start_node_id` | Starting node identifier |
| `edge_types` | Edge types to traverse (e.g., `[derived_from, supports]`) |
| `direction` | Forward, reverse, or both |
| `max_depth` | Maximum traversal depth (default: 3) |
| `filter` | Node property filter (optional) |

**Example**: From artifact A-001, traverse `derived_from` backwards to find all source Events.

### Query (Shortest Path)

Find the shortest path between two nodes along specified edge types.

| Parameter | Description |
|-----------|-------------|
| `source_id` | Starting node ID |
| `target_id` | Target node ID |
| `edge_types` | Allowed edge types |
| `algorithm` | BFS (unweighted) or Dijkstra (weighted) |

**Example**: Find shortest path from entity AG-042 to concept "Authentication".

### Subgraph

Extract a subgraph around a node or set of nodes.

| Parameter | Description |
|-----------|-------------|
| `center_node_ids` | Center node IDs |
| `radius` | Traversal radius (default: 2) |
| `edge_types` | Edge types to include |
| `max_nodes` | Maximum nodes in subgraph (default: 100) |

**Example**: Extract the knowledge neighborhood of a strategic decision artifact.

### Analyze

Run analytical queries on the graph structure.

| Analysis | Description |
|----------|-------------|
| `degree_centrality` | Find most-connected artifacts and entities |
| `community_detection` | Identify knowledge clusters and domains |
| `contradiction_clusters` | Find groups of mutually contradictory artifacts |
| `knowledge_coverage` | Measure concept coverage breadth |
| `gap_analysis` | Identify concepts with low artifact support |

## Graph Storage and Indexing

| Aspect | Strategy |
|--------|----------|
| Primary storage | Dedicated graph database (e.g., Dgraph, Neo4j) |
| Index | B-tree on node IDs, inverted index on concept names |
| Edge index | Adjacency list with edge type as key |
| Cache | LRU cache for hot subgraphs (top 100 most-queried neighborhoods) |
| Snapshot | Daily full graph snapshots for disaster recovery |
| Replication | Read replicas for query load (active-passive) |

### Graph Update Protocol

When a knowledge artifact is accepted, the graph is updated atomically:

```
1. Create KnowledgeArtifact node
2. Create derived_from edges to source Events
3. Create categorizes edges to Concepts (extracted from metadata)
4. Evaluate supports/contradicts edges against existing accepted artifacts
5. Create supersedes edges if deprecating previous artifacts
6. Commit transaction (all or nothing)
```

## Integration with KMS

| Concern | KMS | Knowledge Graph |
|---------|-----|-----------------|
| Storage | Artifact content and versioning | Relationships and structure |
| Primary operation | CRUD on artifacts | Traversal and analysis |
| Query | By ID, type, status | By path, neighbourhood, centrality |
| Consistency | Strong (event log) | Eventual (graph projection from events) |

The Knowledge Graph is a projection of KMS data plus relationship analysis. It is not the authoritative store — the KMS event log is. The graph can be rebuilt from the KMS event log at any time.

## Graph Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `KG.NodeCreated` | New node added to graph | node_id, node_type, properties |
| `KG.EdgeCreated` | New edge added between two nodes | edge_id, source_id, target_id, edge_type |
| `KG.EdgeWeightUpdated` | Edge weight changed | edge_id, old_weight, new_weight |
| `KG.NodeRemoved` | Node removed (artifact archived) | node_id |
| `KG.SubgraphQueried` | Subgraph extraction query executed | center_node_ids, radius, result_size |
| `KG.PathFound` | Shortest path query result | source_id, target_id, path_length |
| `KG.AnalysisCompleted` | Graph analysis completed | analysis_type, result_summary |

## Cross-Cutting Concerns

### Security

Graph access is scoped by organization (CPR-010). An entity in Organization A cannot traverse into Organization B's knowledge graph nodes unless federation is explicitly configured. Graph queries are authenticated and authorized through ACF.

### Evidence

Every graph mutation is sourced from KMS events. The graph is a derived projection; it cannot be modified independently. All graph operations produce query events for audit.

### Lifecycle

Graph nodes follow the artifact lifecycle status. When an artifact is deprecated, its node remains in the graph but is flagged as deprecated. When archived, it is removed from the active graph and moved to a historical archive.

### Capability Bounds

Graph operations are capability-bounded: `graph.traverse`, `graph.query`, `graph.analyze`. Higher-autonomy entities have broader graph access (PHI-003). Read-only entities cannot mutate the graph.

### Communication

Graph operations are accessed through ACF. The Graph service subscribes to KMS events to keep the graph current. Query results are returned over ACF response topics.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Knowledge Graph does relationships — does not store artifact content |
| R3 | Graph is a derived projection; canonical data is in KMS |
| R9 | Graph queries are deterministic for the same graph state |
| R10 | Graph model uses simple node/edge schema (no hypergraphs) |
| R13 | Graph fails closed on database failure |
| R15 | New edge types can be added without modifying existing traversal code |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Events are nodes in the graph |
| Governance/006-AKM.md | AKM knowledge types map to node types |
| Foundations/005-Architectural-Patterns.md | Graph projection from event log |
| Foundations/002-Design-DNA.md | R1, R3, R9, R10, R13, R15 |
| 002-KMS.md | KMS is the authoritative source for graph data |
| 004-Knowledge-Registry.md | Registry indexes what the graph connects |
| 011-Knowledge-Provenance.md | Provenance uses graph for chain tracing |
| 012-Knowledge-Analytics.md | Analytics uses graph for gap detection |
