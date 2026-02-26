# AIOS Architecture

## Execution Flow

User → Intent → Action → Policy → Executor → System

## Crates

### core

Defines CoreAction and PluginAction.

### policy

Validates and governs all actions.

### executor

Async execution engine (Tokio).

### intent

LLM abstraction and deep reasoning logic.

### plugin-sdk

Defines plugin registration and IPC protocol.

## Security Model

-   AI has read-only controlled system access.
-   Executor is the only component allowed to modify system state.
-   Plugins run in isolated processes.
