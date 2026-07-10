# AIOS SDK
## 002 — Knowledge SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | SDK |
| Document ID | SDK-KNOWLEDGE-002 |
| Source Laws | Law 4 — Evidence, Law 9 — Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge SDK is the interface for building knowledge-aware tools that interact with the Academy — AIOS's learning and knowledge management system. It enables Workers, Organizations, and external tools to search, propose, validate, compose, and execute knowledge artifacts. This document is the developer quick-start. For the complete specification, see `Bible/08-Interfaces/SDK/002-Knowledge-SDK.md`.

## Quick Start

```python
from aios_sdk.knowledge import KnowledgeProvider, KnowledgeQuery

class KnowledgeTool(KnowledgeProvider):
    def search_knowledge(self, query):
        return self._academy.search(query)

    def propose_knowledge(self, artifact):
        # Submit new knowledge for validation
        proposal = self._academy.submit(artifact)
        return proposal.receipt

    def execute_knowledge(self, knowledge_id, context):
        # Execute a knowledge-driven action via KEE
        artifact = self._academy.get(knowledge_id)
        return self._kee.execute(artifact, context)
```

## Installation

```
pip install aios-sdk-knowledge
```

Requires Python 3.11+. Depends on `aios-sdk-core` for ACF communication and Academy integration.

## Core Concepts

### KnowledgeProvider
The base interface for knowledge-aware tools. Handles search, proposal, validation, composition, and execution of knowledge artifacts.

### KnowledgeArtifact
A unit of knowledge — a pattern, insight, rule, or model extracted from evidence and validated by the Academy. Each artifact has a confidence score, source evidence chain, and expiration.

### KEE (Knowledge Execution Engine)
The runtime that executes knowledge-driven actions. Takes a KnowledgeArtifact and context, produces an ExecutionResult.

## Usage Guide

### 1. Search Knowledge

```python
from aios_sdk.knowledge import KnowledgeProvider

class ResearchAssistant(KnowledgeProvider):
    def search_knowledge(self, query):
        results = self._academy.search(
            query=query.text,
            filters={
                "domains": query.domains,
                "min_confidence": 0.7,
                "knowledge_types": ["pattern", "insight"]
            }
        )
        return [
            SearchResult(
                id=r.id,
                title=r.title,
                confidence=r.confidence,
                summary=r.summary[:200]
            )
            for r in results
        ]

    def get_knowledge_graph(self, query):
        return self._academy.query_graph(
            root=query.root_id,
            depth=query.depth or 2,
            relationship_types=["derives_from", "supported_by", "contradicts"]
        )
```

### 2. Propose New Knowledge

```python
def propose_improvement(evidence_chain, academy):
    # Extract pattern from evidence
    pattern = extract_pattern(evidence_chain)

    # Build knowledge artifact
    artifact = KnowledgeArtifact(
        knowledge_type="pattern",
        title="Performance degradation pattern in high-load trading",
        content=pattern.to_dict(),
        source_evidence=[e.event_id for e in evidence_chain],
        confidence=0.6,
        tags=["trading", "performance", "pattern"],
        domain="trading",
        expiration=datetime.now() + timedelta(days=90)
    )

    # Submit for validation
    receipt = academy.propose_knowledge(artifact)
    return receipt
```

### 3. Execute Knowledge

```python
def apply_knowledge(knowledge_id, current_context, knowledge_provider):
    # Dry run first
    dry_result = knowledge_provider.dry_run_knowledge(
        knowledge_id=knowledge_id,
        context=current_context
    )

    if dry_result.risk_score > 0.7:
        raise RiskThresholdExceeded(dry_result.risk_score)

    # Execute
    result = knowledge_provider.execute_knowledge(
        knowledge_id=knowledge_id,
        context=current_context
    )

    return result
```

### 4. Subscribe to Knowledge Topics

```python
def monitor_knowledge(provider):
    handle = provider.subscribe_to_topic(
        topic="academy.knowledge.updated"
    )

    while True:
        notifications = provider.get_notifications(
            filter={"since": handle.last_check}
        )
        for notification in notifications:
            if notification.knowledge_type == "security.pattern":
                apply_security_pattern(notification.artifact)
        time.sleep(10)
```

## Implementation Checklist

- [ ] Implement all `KnowledgeProvider` interface methods
- [ ] Support structured knowledge queries (search, graph, similarity, recommendation)
- [ ] Handle knowledge proposal lifecycle (submitted → validating → verified → accepted → indexed → distributed)
- [ ] Validate knowledge artifacts against constitutional bounds before submission
- [ ] Support knowledge composition (combine multiple artifacts into new insight)
- [ ] Implement `dryRunKnowledge` for safe preview
- [ ] Handle KEE execution context (session_id, capability bounds, resource allocation)
- [ ] Support topic subscriptions for real-time knowledge notifications
- [ ] Respect knowledge confidence scores (min confidence filter)
- [ ] Handle knowledge expiration (do not return expired artifacts by default)
- [ ] Log errors with unique error codes (R12 compliance)
- [ ] Test with `aios-sdk-knowledge test` conformance suite

## Common Patterns

### Knowledge-Driven Optimization
```python
def optimize_runtime(runtime_id, knowledge_provider):
    # Search for relevant knowledge
    query = KnowledgeQuery(
        text=f"optimization patterns for {runtime_id}",
        domains=["runtime", "performance"],
        min_confidence=0.6
    )
    patterns = knowledge_provider.search_knowledge(query)

    # Apply each pattern
    for pattern in patterns:
        result = knowledge_provider.dry_run_knowledge(
            pattern.id,
            context={"runtime_id": runtime_id}
        )
        if result.expected_improvement > 0.1:
            knowledge_provider.execute_knowledge(
                pattern.id,
                context={"runtime_id": runtime_id}
            )
```

### Evidence-Based Knowledge Validation
```python
def validate_knowledge_proposal(artifact, academy, event_store):
    # Verify source evidence exists
    for evidence_id in artifact.source_evidence:
        event = event_store.get_event(evidence_id)
        if not event:
            return ValidationResult(
                valid=False,
                reason=f"Source evidence {evidence_id} not found"
            )

    # Verify evidence chain integrity
    chain = event_store.get_chain(artifact.source_evidence[0])
    if not chain.verify():
        return ValidationResult(
            valid=False,
            reason="Source evidence chain integrity check failed"
        )

    return academy.validate_knowledge(artifact)
```

## Conformance Testing

```
aios-sdk-knowledge test --provider my_tool.MyKnowledgeTool
```

Tests check:
- All interface methods implemented
- Knowledge queries return correctly filtered results
- Proposal lifecycle completes (submitted → accepted/rejected)
- Knowledge execution produces correct results
- Dry run produces same result as execution (no side effects)
- Knowledge graph queries return valid graph structures
- Topic subscriptions deliver expected notifications
- Expired artifacts are excluded from results by default

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/08-Interfaces/SDK/002-Knowledge-SDK.md | Complete SDK specification |
| Bible/02-Core/Academy/000-Overview.md | Academy architecture |
| Bible/02-Core/Academy/013-KEE.md | Knowledge Execution Engine |
| Bible/02-Core/Academy/002-KMS.md | Knowledge Management System |
| Bible/02-Core/Academy/003-Knowledge-Graph.md | Knowledge graph specification |
| Reference/002-Reference-Architecture.md | System architecture overview |
