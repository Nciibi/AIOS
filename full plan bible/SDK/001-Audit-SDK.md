# AIOS SDK
## 001 — Audit SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | SDK |
| Document ID | SDK-AUDIT-001 |
| Source Laws | Law 3 — Communication, Law 4 — Evidence, Law 8 — Verification-First |
| Source Physics | Physics/005-Events.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Audit SDK is the interface for building audit and evidence tools — compliance monitors, forensic investigators, real-time alerting systems, and regulatory reporting tools. This document is the developer quick-start. For the complete specification, see `Bible/08-Interfaces/SDK/001-Audit-SDK.md`.

## Quick Start

```python
from aios_sdk.audit import AuditProvider, EventFilter

class ComplianceMonitor(AuditProvider):
    def query_events(self, filter):
        # Query Events from the Event Store
        return self._event_store.query(filter)

    def verify_chain(self, event_id):
        # Verify Merkle-DAG chain integrity
        chain = self._event_store.get_chain(event_id)
        return self._crypto.verify_chain(chain)

    def check_compliance(self, filter, standard):
        events = self.query_events(filter)
        violations = []
        for event in events:
            if not self._compliance_check(event, standard):
                violations.append(event.event_id)
        return ComplianceReport(passed=len(violations) == 0, violations=violations)
```

## Installation

```
pip install aios-sdk-audit
```

Requires Python 3.11+. Depends on `aios-sdk-core` for ACF communication and event schema validation.

## Core Concepts

### AuditProvider
The base interface for all audit tools. Handles event querying, chain verification, pattern analysis, compliance checking, and evidence packaging.

### Event
An immutable record of an action. Every operation in AIOS produces at least one Event. Events form a Merkle-DAG chain for integrity verification.

### Evidence Package
A cryptographically sealed collection of Events and verification proofs, used for legal, regulatory, and compliance purposes.

## Usage Guide

### 1. Implement a Monitor

```python
from aios_sdk.audit import AuditProvider, EventFilter, AnomalyReport

class SecurityMonitor(AuditProvider):
    def __init__(self, event_store, baseline):
        self._event_store = event_store
        self._baseline = baseline

    def detect_anomaly(self, filter, baseline=None):
        events = list(self.query_events(filter))
        baseline = baseline or self._baseline
        anomalies = []

        for event in events:
            deviation = self._score_deviation(event, baseline)
            if deviation > 0.8:
                anomalies.append(AnomalyReport(
                    event_id=event.event_id,
                    score=deviation,
                    reason=f"Deviation from baseline: {deviation:.2f}"
                ))

        return anomalies

    def stream_events(self, filter):
        return self._event_store.subscribe(filter)

    def register_as_observer(self):
        return self._event_store.register_observer(
            callback=self._on_event,
            filter=EventFilter(event_types=["security.*", "auth.*"])
        )
```

### 2. Verify Event Chain Integrity

```python
def verify_audit_trail(event_id, event_store, crypto):
    chain = event_store.get_chain(event_id)

    # Verify every link in the chain
    for i in range(1, len(chain)):
        current = chain[i]
        previous = chain[i-1]

        # Verify hash link
        expected_hash = crypto.hash(previous.content + previous.hash)
        if current.previous_hash != expected_hash:
            return ChainVerificationResult(
                valid=False,
                broken_link=i,
                reason="Hash mismatch in chain"
            )

    return ChainVerificationResult(valid=True, chain_length=len(chain))
```

### 3. Generate Evidence Package

```python
def generate_evidence(event_ids, event_store, crypto):
    package = EvidencePackage(case_id=uuid4())

    for event_id in event_ids:
        event = event_store.get_event(event_id)
        chain = event_store.get_chain(event_id)
        proof = crypto.seal(event)

        package.add_evidence(
            event=event,
            chain_proof=chain,
            seal=proof
        )

    package.finalize()
    return package
```

## Implementation Checklist

- [ ] Implement all `AuditProvider` interface methods
- [ ] Support `EventFilter` with time range, event types, source entities, correlation ID
- [ ] Verify Merkle-DAG chain integrity in `verify_chain`
- [ ] Support real-time event streaming via `streamEvents`
- [ ] Implement pattern analysis in `analyzePattern`
- [ ] Support compliance checks against configurable standards
- [ ] Handle evidence package generation with cryptographic seals
- [ ] Register as observer for real-time notifications
- [ ] Respect event retention policies (tiered: Critical/Operational/Debug/Transient)
- [ ] Log errors with unique error codes (R12 compliance)
- [ ] Test with `aios-sdk-audit test` conformance suite

## Common Patterns

### Real-Time Alerting
```python
def register_as_observer(self):
    def on_event(event):
        if event.type == "security.violation" and event.severity >= 8:
            self._alert(event)

    return self._event_store.register_observer(
        callback=on_event,
        filter=EventFilter(event_types=["security.*"])
    )
```

### Compliance Dashboard
```python
def generate_report(self, org_id, timeframe):
    filter = EventFilter(
        time_range=timeframe,
        source_entities=[org_id]
    )

    events = list(self.query_events(filter))
    violations = [e for e in events if e.type == "compliance.violation"]

    return AuditReport(
        org_id=org_id,
        total_events=len(events),
        violations=len(violations),
        compliance_score=1.0 - (len(violations) / max(len(events), 1))
    )
```

## Conformance Testing

```
aios-sdk-audit test --provider my_monitor.MyMonitor
```

Tests check:
- All interface methods implemented
- Event queries return correct filters
- Chain verification detects tampering
- Real-time streaming delivers events within SLO
- Evidence packages are cryptographically verifiable
- Anomaly detection scores are deterministic for same inputs

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/08-Interfaces/SDK/001-Audit-SDK.md | Complete SDK specification |
| Bible/04-Execution/Security/Audit/000-EAS.md | Evidence Audit Service |
| Bible/05-Platform/005-AUS.md | Audit Service specification |
| Bible/05-Platform/004-EVS.md | Event Store specification |
| Bible/00-Foundations/003-Core-Principles.md | Evidence-driven design principles |
| Reference/002-Reference-Architecture.md | System architecture overview |
