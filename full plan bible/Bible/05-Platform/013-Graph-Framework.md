# AIOS Bible — Platform
## 013 — Graph Framework

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Platform |
| Document ID | AIOS-BBL-005-GF-000 |
| Source Laws | Law 9 — Law of Design DNA (R9 Determinism) |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Graph processing framework used by Knowledge Graph, Organization hierarchy, and dependency analysis. The Graph Framework provides a generic, deterministic graph model with traversal, query, and analysis capabilities. It supports directed and undirected graphs, weighted and unweighted edges, and labeled nodes and edges with an optional property store.

## Graph Model

```
Graph {
  id: UUID,
  name: string,
  type: directed | undirected | mixed,
  weighted: bool,
  node_count: int,
  edge_count: int,
  nodes: map<UUID, Node>,
  edges: map<UUID, Edge>,
  properties: PropertyStore
}

Node {
  id: UUID,
  labels: string[],          // e.g., ["Person", "Agent"]
  properties: map<string, any>,
  created_at: timestamp
}

Edge {
  id: UUID,
  source: UUID,              // source node ID
  target: UUID,              // target node ID
  labels: string[],          // e.g., ["KNOWS", "DEPENDS_ON"]
  weight: float?,            // optional weight
  directed: bool,            // true for directed edges
  properties: map<string, any>,
  created_at: timestamp
}
```

### Property Store

The property store provides optional key-value storage on nodes and edges:

```
PropertyStore {
  backend: "in_memory" | "rocksdb" | "postgres",
  indexing: string[],        // indexed property keys
  max_value_size: int        // max property value (default 64KB)
}
```

## Graph Operations

### Mutation Operations

```
createGraph(name, type, weighted, config?) → graph_id
deleteGraph(graph_id) → void
addNode(graph_id, labels, properties) → node_id
addEdge(graph_id, source, target, labels, weight?, properties) → edge_id
removeNode(graph_id, node_id, cascade?) → void
removeEdge(graph_id, edge_id) → void
updateNode(graph_id, node_id, labels?, properties?) → void
updateEdge(graph_id, edge_id, labels?, weight?, properties?) → void
clearGraph(graph_id) → void
```

### Query Operations

```
getNode(graph_id, node_id) → Node
getEdge(graph_id, edge_id) → Edge
getNeighbors(graph_id, node_id, direction?, labels?) → Node[]
getAdjacentEdges(graph_id, node_id, direction?, labels?) → Edge[]
getDegree(graph_id, node_id, direction?) → int
queryNodes(graph_id, query) → Node[]
queryEdges(graph_id, query) → Edge[]
existsNode(graph_id, node_id) → bool
existsEdge(graph_id, source, target) → bool
```

### Traversal Operations

```
traverseBFS(graph_id, start_node, visitor, max_depth?) → TraversalResult
traverseDFS(graph_id, start_node, visitor, max_depth?) → TraversalResult
shortestPath(graph_id, source, target, weight_fn?) → Path
shortestPaths(graph_id, source, target, max_results?) → Path[]
subgraph(graph_id, node_ids) → Graph
connectedComponent(graph_id, node_id) → Graph
```

### Analysis Operations

```
connectedComponents(graph_id) → Graph[]
degreeCentrality(graph_id, node_id) → float
betweennessCentrality(graph_id, node_ids?) → map<node_id, float>
pageRank(graph_id, iterations?, damping?) → map<node_id, float>
detectCycles(graph_id) → Cycle[]
detectCommunities(graph_id, algorithm?) → map<node_id, int>
```

## Query Language

The Graph Framework supports a Cypher-like query language:

### Pattern Matching

```
MATCH (n:Person)-[e:KNOWS]->(m:Person)
WHERE n.name = "Alice"
RETURN m.name, e.weight
```

### Supported Clauses

| Clause | Description | Example |
|--------|-------------|---------|
| MATCH | Pattern matching | `MATCH (n)-[e]->(m)` |
| WHERE | Filter conditions | `WHERE n.age > 30` |
| RETURN | Output specification | `RETURN n.name, m.name` |
| ORDER BY | Sort results | `ORDER BY n.name ASC` |
| LIMIT | Limit results | `LIMIT 10` |
| CREATE | Create nodes/edges | `CREATE (n:Person {name: "Bob"})` |
| DELETE | Delete nodes/edges | `DELETE n, e` |
| SET | Update properties | `SET n.age = 31` |

## Graph Storage

| Component | Storage Engine | Schema | Indexing |
|-----------|---------------|--------|----------|
| Adjacency list | RocksDB/in-memory | Custom serialization | By node ID |
| Node index | B-tree | Node ID → Node | By label, by property |
| Edge index | B-tree | Edge ID → Edge | By source, by target, by label |
| Property store | RocksDB/Postgres | Key-value | Configurable per graph |
| Full-text index | Inverted index | Token → Node/Edge | Text properties only |

## Determinism

All graph operations are deterministic (R9):

| Operation | Determinism Guarantee |
|-----------|----------------------|
| Add node | Same properties → same node ID (if ID is content-hash) |
| Add edge | Same source, target, labels → same edge ID |
| Traversal (BFS/DFS) | Same graph + same start → same traversal order |
| Shortest path | Same graph → same path (Dijkstra with tiebreaking) |
| PageRank | Same graph + same params → identical scores |
| Connected components | Same graph → identical component assignment |

Tiebreaking: when multiple nodes have equal priority, sort by node ID (stable order).

## Performance Characteristics

| Operation | Time Complexity | Benchmarked (10K nodes) |
|-----------|----------------|------------------------|
| Add node | O(1) | <0.1ms |
| Add edge | O(1) | <0.1ms |
| Get neighbors | O(degree) | <0.5ms |
| BFS traversal | O(V+E) | <10ms |
| Shortest path | O((V+E) log V) | <50ms |
| PageRank (10 iterations) | O(iter * (V+E)) | <200ms |
| Connected components | O(V+E) | <20ms |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| GF-001 | GraphNotFound | No graph with the given ID |
| GF-002 | NodeNotFound | No node with the given ID in graph |
| GF-003 | EdgeNotFound | No edge with the given ID in graph |
| GF-004 | NodeAlreadyExists | Node already in graph |
| GF-005 | EdgeAlreadyExists | Edge already exists between nodes |
| GF-006 | InvalidQuery | Query syntax or semantics error |
| GF-007 | CycleDetected | Operation would create a cycle in DAG |
| GF-008 | PropertyNotFound | Required property not found |
| GF-009 | LabelNotFound | Label does not exist in graph |

## Graph Framework Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `GF.GraphCreated` | New graph created | graph_id, name, type, weighted, initial_config |
| `GF.GraphDeleted` | Graph removed | graph_id, name, node_count, edge_count |
| `GF.GraphCleared` | Graph content cleared | graph_id, node_count, edge_count |
| `GF.NodeAdded` | Node added to graph | graph_id, node_id, labels, properties_hash |
| `GF.NodeRemoved` | Node removed | graph_id, node_id, labels, edge_count_affected |
| `GF.EdgeAdded` | Edge added | graph_id, edge_id, source, target, labels, weight |
| `GF.EdgeRemoved` | Edge removed | graph_id, edge_id, source, target, labels |
| `GF.QueryExecuted` | Query run | graph_id, query_type, result_count, duration_ms |
| `GF.AnalysisCompleted` | Analysis operation done | graph_id, operation, result_summary |

## Cross-Cutting Concerns

### Security

Graph access requires authentication. Graph operations are authorized. Graph data access is scoped by entity authorization. Query results respect data access controls.

### Evidence

Every graph mutation produces an Event. Query operations are logged when they access sensitive data. Graph creation and deletion are audit Events.

### Lifecycle

Graphs follow: Created → Active → Updating → Archived → Deleted. The Graph Framework follows Platform service lifecycle. Graph schemas are versioned.

### Capability Bounds

The Graph Framework only manages graph data structures and traversals. It does not interpret graph meaning, does not store domain-specific data (consumers do), and does not enforce business rules.

### Communication

The Graph Framework communicates through ACF. Graph operations arrive via ACF messages. Query results are returned through ACF response streams.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Framework does one thing: graph processing |
| R2 — Dependency Order | Framework depends on ACF; no upward deps |
| R3 — DRY | Graph structure is stored once; consumers query it |
| R4 — Builder Pattern | Graphs are built by GraphBuilders with schema validation |
| R5 — Liskov | All graph storage backends implement the same GraphStore interface |
| R6 — DI over Singletons | Framework receives ACF as injected dependency |
| R7 — Tests Exist | Every traversal algorithm and query type has tests |
| R8 — Tests Fast | Graph queries complete in <10ms for typical graphs |
| R9 — Deterministic | Same graph + same query always produces same result |
| R10 — Simpler Over Complex | Graph model is minimal; advanced features opt-in |
| R11 — Refactor Over Rewrite | Graph schema evolves via versioned updates |
| R12 — Embrace Errors | Every query failure has a unique error code |
| R13 — Design for Failure | Graph is immutable snapshot; read-only operations continue |
| R14 — Paved Path | Graph Framework is the only path for graph storage and query |
| R15 — Open/Closed | New traversal algorithms extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Core/Academy/003-Knowledge-Graph.md | Knowledge Graph uses Graph Framework |
| Organizations/003-ODS.md | Organization hierarchy uses Graph Framework |
| Core/DTS/004-Confidence.md | DTS dependency graphs use Graph Framework |
| Physics/011-Design-DNA.md | R9 determinism is a core invariant |
