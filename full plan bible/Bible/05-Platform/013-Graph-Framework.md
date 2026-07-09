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
  type: directed | undirected | mixed,
  weighted: bool,
  nodes: Node[],
  edges: Edge[],
  properties: PropertyStore
}

Node {
  id: UUID,
  labels: string[],
  properties: map<string, any>
}

Edge {
  id: UUID,
  source: UUID,
  target: UUID,
  labels: string[],
  weight: float?,
  properties: map<string, any>,
  directed: bool
}
```

## Graph Operations

### Mutation Operations

```
createGraph(type, weighted, config) → graph_id
addNode(graph_id, labels, properties) → node_id
addEdge(graph_id, source, target, labels, weight?, properties) → edge_id
removeNode(graph_id, node_id) → void
removeEdge(graph_id, edge_id) → void
updateNode(graph_id, node_id, updates) → void
updateEdge(graph_id, edge_id, updates) → void
```

### Query Operations

```
getNode(graph_id, node_id) → Node
getEdge(graph_id, edge_id) → Edge
getNeighbors(graph_id, node_id, direction?) → Node[]
getAdjacentEdges(graph_id, node_id, direction?) → Edge[]
queryNodes(graph_id, query) → Node[]
queryEdges(graph_id, query) → Edge[]
```

### Traversal Operations

```
traverseBFS(graph_id, start_node, visitor_fn) → TraversalResult
traverseDFS(graph_id, start_node, visitor_fn) → TraversalResult
shortestPath(graph_id, source, target, weight_fn?) → Path
subgraph(graph_id, node_ids) → Graph
```

### Analysis Operations

```
connectedComponents(graph_id) → Graph[]
degreeCentrality(graph_id, node_id) → float
pageRank(graph_id, iterations?) → map<node_id, float>
detectCycles(graph_id) → Cycle[]
```

## Query Language

The Graph Framework supports a Cypher-like query language for pattern matching:

```
MATCH (n:Person)-[e:KNOWS]->(m:Person)
WHERE n.name = "Alice"
RETURN m.name, e.weight
```

Supported clauses: MATCH, WHERE, RETURN, ORDER BY, LIMIT, CREATE, DELETE, SET.

## Graph Storage

| Component | Storage Engine | Description |
|-----------|---------------|-------------|
| **Adjacency list** | In-memory/disk-backed | Core graph structure |
| **Node index** | B-tree by label | Fast node lookup |
| **Edge index** | B-tree by source/target | Fast edge lookup |
| **Property store** | Key-value | Optional properties on nodes/edges |

## Determinism

All graph operations are deterministic (R9). Given the same graph and the same query, the framework always produces the same result. Traversal order is deterministic (BFS and DFS use stable ordering). Pathfinding returns the same path for identical inputs. PageRank produces identical scores for the same graph and iteration count.

## Graph Framework Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `GF.GraphCreated` | A new graph is created | graph_id, type, weighted, node_count, edge_count |
| `GF.GraphDeleted` | A graph is removed | graph_id, node_count, edge_count |
| `GF.NodeAdded` | A node is added to a graph | graph_id, node_id, labels |
| `GF.NodeRemoved` | A node is removed | graph_id, node_id, edge_count_affected |
| `GF.EdgeAdded` | An edge is added | graph_id, edge_id, source, target, weight |
| `GF.EdgeRemoved` | An edge is removed | graph_id, edge_id, source, target |
| `GF.QueryExecuted` | A query is run | graph_id, query_type, result_count, duration_ms |

## Cross-Cutting Concerns

### Security

Graph access requires authentication. Graph operations are authorized by the Security Council. Graph data access is scoped by entity authorization. Query results respect data access controls.

### Evidence

Every graph mutation produces an Event. Query operations are logged when they access sensitive data. Graph creation and deletion are audit Events.

### Lifecycle

Graphs follow: Created → Active → Updating → Archived → Deleted. The Graph Framework follows Platform service lifecycle. Graph schemas are versioned.

### Capability Bounds

The Graph Framework only manages graph data structures and traversals. It does not interpret graph meaning, does not store domain-specific data (consumers do), and does not enforce business rules. Graph capabilities are limited to: store, query, traverse, and analyze graph structures.

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
