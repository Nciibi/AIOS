# AIOS SDK
## 000 — Runtime SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | SDK |
| Document ID | SDK-RUNTIME-000 |
| Source Laws | Law 3 — Communication, Law 4 — Evidence, Law 9 — Design DNA |
| Source Physics | Physics/005-Events.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Runtime SDK is the interface for building runtime execution providers — backends that instantiate and run AIOS Workers. This document is the developer quick-start: installation, basic usage, common patterns, and implementation checklist. For the complete specification, see `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`.

## Quick Start

```python
from aios_sdk.runtime import RuntimeProvider, Session, Capability

class MyProvider(RuntimeProvider):
    def create_session(self, genome, allocation):
        session = Session(
            session_id=genome.entity_id,
            genome=genome,
            allocation=allocation
        )
        return session

    def invoke_capability(self, session_id, capability, payload):
        # Execute the capability within the session
        result = self._execute(session_id, capability, payload)
        return result
```

## Installation

```
pip install aios-sdk-runtime
```

Requires Python 3.11+. The SDK depends on `aios-sdk-core` (ACF communication, identity verification, evidence recording).

## Core Concepts

### RuntimeProvider
The base interface every provider implements. Handles session lifecycle, capability invocation, resource accounting, and health reporting.

### Session
A Worker execution context. Created from a Genome, bounded by a ResourceAllocation. Lifecycle: Created → Starting → Running ↔ Paused → Terminating → Terminated.

### Capability
An executable action within a session. Must be declared in the session's capability bounds. Verified by the Security Council before execution.

## Usage Guide

### 1. Implement the Provider

```python
from aios_sdk.runtime import RuntimeProvider, SessionStatus

class CodeExecutionProvider(RuntimeProvider):
    def __init__(self):
        self.sessions = {}

    def create_session(self, genome, allocation):
        session_id = genome.entity_id
        sandbox = Sandbox(allocation)
        self.sessions[session_id] = {
            "sandbox": sandbox,
            "status": SessionStatus.CREATED,
            "genome": genome
        }
        return session_id

    def start_session(self, session_id):
        session = self.sessions[session_id]
        session["sandbox"].start()
        session["status"] = SessionStatus.RUNNING
        self._emit_event("session.started", {"session_id": session_id})

    def invoke_capability(self, session_id, capability, payload):
        session = self.sessions[session_id]
        if capability.type == "code.execution":
            return session["sandbox"].execute(payload["code"])
        raise CapabilityNotSupported(capability.type)

    def health_check(self):
        return {"status": "healthy", "sessions": len(self.sessions)}
```

### 2. Register with the Runtime Manager

```python
from aios_sdk.runtime import register_provider

provider = CodeExecutionProvider()
register_provider(
    provider=provider,
    name="code-execution",
    version="1.0.0",
    capabilities=["code.execution", "sandbox.run"]
)
```

### 3. Handle Events

Every provider method should emit Events for audit:

```python
def terminate_session(self, session_id):
    session = self.sessions.pop(session_id, None)
    if session:
        session["sandbox"].cleanup()
        self._emit_event("session.terminated", {
            "session_id": session_id,
            "reason": "normal",
            "duration_ms": session["duration"]
        })
```

## Implementation Checklist

- [ ] Implement all `RuntimeProvider` interface methods
- [ ] Handle session lifecycle states correctly (Created → Starting → Running ↔ Paused → Terminating → Terminated)
- [ ] Emit Events for every lifecycle transition
- [ ] Enforce resource allocation limits (CPU, memory, disk, network)
- [ ] Support capability bounds checking before execution
- [ ] Implement health check endpoint
- [ ] Report usage metrics for accounting
- [ ] Handle graceful shutdown on `terminate_session`
- [ ] Handle force shutdown on timeout (configurable per session)
- [ ] Log errors with unique error codes (R12 compliance)
- [ ] Test with `aios-sdk-runtime test` conformance suite

## Common Patterns

### Streaming Capabilities
```python
def invoke_capability(self, session_id, capability, payload):
    if capability.type == "llm.inference":
        for chunk in self._stream_inference(payload):
            self._emit_event("capability.chunk", {"data": chunk})
            yield chunk
```

### Resource Enforcement
```python
def create_session(self, genome, allocation):
    if allocation.cpu_cores > self._available_cpu():
        raise ResourceExceeded("cpu", allocation.cpu_cores, self._available_cpu())
    return super().create_session(genome, allocation)
```

### Error Handling
```python
def invoke_capability(self, session_id, capability, payload):
    try:
        return self._execute(session_id, capability, payload)
    except SandboxError as e:
        raise ProviderError("RUNTIME_001", f"Sandbox failure: {e}")
    except TimeoutError:
        raise ProviderError("RUNTIME_002", "Capability timed out")
```

## Conformance Testing

Run the SDK conformance suite to verify your provider:

```
aios-sdk-runtime test --provider my_provider.MyProvider
```

Tests check:
- All interface methods implemented and return correct types
- Session lifecycle transitions match the state machine
- Events are emitted for all state changes
- Resource limits are enforced
- Errors use unique codes and include context
- Provider handles concurrent sessions correctly

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/08-Interfaces/SDK/000-Runtime-SDK.md | Complete SDK specification |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime architecture |
| Bible/04-Execution/Runtime/001-SDK.md | SDK integration details |
| Bible/02-Core/AGS/000-Overview.md | Genome system — session templates |
| Bible/02-Core/ROS/000-Overview.md | Resource allocation |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | Execution authorization |
| Reference/002-Reference-Architecture.md | System architecture overview |
