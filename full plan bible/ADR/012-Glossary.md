# AIOS DNA
## Document 012 — Glossary

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | DNA |
| Document ID | AIOS-DNA-012 |
| Applies To | Entire AIOS Platform |

---

# Purpose

This document provides a quick reference for the official terminology used throughout AIOS.

Unlike the Terminology document, which formally specifies every concept, the Glossary serves as an alphabetical index.

Its purpose is to help contributors quickly understand AIOS vocabulary while reading specifications, RFCs and source code.

When conflicts exist, AIOS-DNA-002 (Terminology) always takes precedence.

---

# A

## Academy

The permanent subsystem responsible for preserving collective intelligence.

Contains Skills, Knowledge, Experience, Templates, Benchmarks and Training assets.

---

## ACF

Abbreviation for AI Communication Fabric.

The universal communication infrastructure connecting every AIOS subsystem.

---

## Actor

An entity capable of initiating work.

Examples include Humans, Automation Rules and External Systems.

---

## AIObject

The universal base object inherited by every first-class object inside AIOS.

Provides identity, ownership, lifecycle, metadata and audit information.

---

## AIOS

Artificial Intelligence Operating System.

A platform responsible for orchestrating autonomous intelligence.

---

# B

## Benchmark

A measurable standard used to evaluate Skills, Workers, Organizations or Runtime performance.

---

## Budget

The collection of resources allocated to a Mission or Worker.

Examples include:

• Tokens

• Time

• Memory

• CPU

• GPU

• Money

---

# C

## Capability

An abstract ability requested by Sou and provided by one or more Runtimes.

Capabilities remain stable regardless of implementation.

---

## Command

A message requesting an action.

Commands are transported through ACF.

---

## Context

The information available to a Worker during execution.

Context may include memory, mission objectives, policies and runtime configuration.

---

# D

## Director

The highest authority inside an Organization.

Responsible for strategy and governance.

---

# E

## Engine

A reusable operating-system service with exactly one responsibility.

Examples:

Planner Engine

Runtime Engine

Scheduler Engine

---

## Event

A message describing something that has already happened.

Events are immutable.

---

## Experience

Verified lessons extracted from completed Missions.

Experience answers:

"What worked?"

---

# G

## Goal

A desired outcome defined by a Mission.

Goals are achieved through Objectives.

---

# H

## Human

The highest authority within AIOS.

Humans define objectives.

AIOS determines safe execution.

---

# I

## Identity

The immutable identifier of an AIObject.

Identity persists throughout the object's lifecycle.

---

## Intent

A requested action awaiting Security Kernel verification.

Every execution begins with an Intent.

---

# K

## Knowledge

Verified reusable information.

Knowledge answers:

"What is true?"

Knowledge belongs to the Academy.

---

# L

## Lifecycle

The ordered sequence of states through which an object progresses.

Every AIObject defines a lifecycle.

---

# M

## Manager

Coordinates Supervisors within an Organization.

Responsible for planning and resource allocation.

---

## Memory

Temporary contextual information used during execution.

Memory expires.

Knowledge does not.

---

## Mission

The highest-level unit of meaningful work within AIOS.

Every request becomes exactly one Mission.

---

## Mission Template

A reusable blueprint for creating new Missions.

---

## Model

A specific artificial intelligence model used by a Runtime.

Examples:

Claude Opus

GPT

Gemini

DeepSeek

Models are implementation details.

---

# O

## Objective

A measurable outcome belonging to a Mission.

Multiple Objectives form a Mission.

---

## Organization

A permanent domain-specific structure responsible for accomplishing Missions.

Organizations own Directors, Managers, Supervisors and Workers.

---

# P

## Policy

A deterministic rule used by the Security Kernel to authorize or deny execution.

---

## Prompt

Structured instructions supplied to a Runtime.

Prompts may be included within Skills.

---

## Provider

The platform supplying one or more Runtimes.

Examples:

Anthropic

OpenAI

Google

Ollama

Providers are replaceable.

---

# Q

## Query

A message requesting information.

Queries never modify system state.

---

# R

## Resolver

The Security Kernel component responsible for resolving Intents before policy evaluation.

---

## Runtime

A concrete implementation capable of providing Capabilities.

Examples:

Claude Code

Codex

OpenClaw

OpenCode

Ollama

---

## Runtime Adapter

A compatibility layer allowing AIOS to communicate with a Runtime.

---

# S

## Scheduler

The Engine responsible for ordering execution.

---

## Security Kernel

The subsystem responsible for deterministic trust and execution authorization.

---

## Session

A live execution instance.

Examples include Worker Sessions, Voice Sessions and Runtime Sessions.

---

## Skill

A reusable package of expertise distributed through the Academy.

Skills may contain Knowledge, Prompts, Examples, Policies and Tools.

---

## Sou

The strategic intelligence of AIOS.

Responsible for reasoning, planning and orchestration.

Never performs direct execution.

---

## Stream

A continuous flow of information transported through ACF.

Examples include voice, logs and telemetry.

---

## Supervisor

Coordinates Workers and monitors execution.

---

# T

## Task

An internal execution step performed by a Worker.

Tasks are components of Missions.

Users interact with Missions rather than individual Tasks.

---

## Template

A reusable blueprint.

Examples include Mission Templates, Worker Templates and Organization Templates.

---

## Topic

A named communication channel within ACF used for publish-subscribe messaging.

---

# U

## User

A Human interacting with AIOS.

Users define goals and approve strategic decisions.

---

# V

## Verification

The process of confirming correctness before accepting an action, Skill or Experience.

---

# W

## Worker

A temporary execution unit responsible for completing assigned Tasks.

Workers own no permanent intelligence.

---

## Worker Session

A running instance of a Worker Template.

Destroyed when work completes.

---

## Worker Template

A reusable blueprint defining how Workers are created.

---

## Workflow

The ordered sequence of Tasks required to complete a Mission.

---

# Z

## Zero Trust

The security philosophy that every action begins untrusted and must earn execution through deterministic verification.

---

# Related Documents

AIOS-DNA-002 — Terminology

AIOS-DNA-003 — Taxonomy

AIOS-DNA-011 — Language Standard

---

# Rationale

A common vocabulary accelerates onboarding, reduces ambiguity and improves communication across documentation, source code and community discussions.

The Glossary serves as a convenient reference while the Terminology document remains the authoritative specification.

---

# Future Extensions

Future versions may introduce additional terms as new subsystems are added.

All new glossary entries must correspond to formally defined terminology.

---

# Final Statement

Language is the foundation of architecture.

A shared vocabulary enables a shared understanding.

A shared understanding enables a coherent operating system.

The Glossary exists to make AIOS approachable without sacrificing precision.