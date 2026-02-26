# AIOS --- AI-Assisted Operating Runtime

AIOS is a Rust-based agent runtime that transforms system interaction
into intent-driven workflows.

## Vision

AI proposes structured actions. Policy governs. Executor executes
deterministically.

## Architecture

Multi-crate workspace: - core - policy - executor - intent -
plugin-sdk - cli

## Principles

-   Strongly typed CoreAction
-   No raw shell execution
-   Policy is authoritative
-   Plugins are sandboxed
-   Deep reasoning is bounded

## Roadmap

Phase 1: Core + Policy\
Phase 2: Executor\
Phase 3: Intent integration\
Phase 4: Plugin supervisor
