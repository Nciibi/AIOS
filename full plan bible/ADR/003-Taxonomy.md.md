# AIOS DNA
## Document 003 — Taxonomy

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | DNA |
| Applies To | Entire AIOS Platform |

---

# Purpose

This document defines the classification system of AIOS.

Terminology defines what things mean.

Taxonomy defines how things are organized.

Every first-class object inside AIOS belongs to exactly one category.

These categories define responsibilities, ownership, lifecycle, persistence, security requirements, and interactions.

---

# AIOS Taxonomy Overview

```
AIOS

├── Actors
├── Strategic Objects
├── Structural Objects
├── Execution Objects
├── Intelligence Assets
├── Communication Objects
├── Trust Objects
├── Runtime Objects
├── System Services
├── System Resources
├── Knowledge Objects
├── Interaction Objects
└── Infrastructure
```

---

# Actors

Actors initiate or influence work.

Examples

• Human User

• Automation Rule

• Scheduled Trigger

• External System

Actors create intent.

Actors never execute directly.

---

# Strategic Objects

Strategic objects define goals.

Examples

Mission

Mission Template

Mission Plan

Mission Graph

Mission Policy

Responsibilities

• Goal definition

• Planning

• Progress

• Completion

---

# Structural Objects

Structural objects define permanent organization.

Examples

Organization

Director

Manager

Supervisor

Department

Team

Responsibilities

• Governance

• Structure

• Ownership

• Scaling

---

# Execution Objects

Execution objects perform work.

Examples

Worker Template

Worker Session

Execution Context

Workspace

Task

Checkpoint

Responsibilities

• Execute

• Report

• Finish

Execution objects are temporary.

---

# Intelligence Assets

Intelligence assets increase capability.

Examples

Skill

Knowledge

Experience

Training Package

Prompt

Benchmark

Pattern

Mission Template

Organization Template

These assets belong to the Academy.

---

# Communication Objects

Everything related to ACF.

Examples

Message

Command

Query

Event

Notification

Broadcast

Topic

Channel

Stream

Subscription

Reply

Request

Communication objects never perform work.

They transport information.

---

# Trust Objects

Everything related to deterministic security.

Examples

Intent

Capability

Policy

Permission

Risk Report

Execution Plan

Audit Record

Verification Token

Trust Objects belong exclusively to the Security Kernel.

---

# Runtime Objects

Concrete execution providers.

Examples

Runtime

Provider

Adapter

Model

Capability Mapping

Runtime Session

Runtime Configuration

Runtime Objects abstract implementations.

---

# System Services

Reusable operating system services.

Examples

Planner Engine

Runtime Engine

Scheduler Engine

Identity Engine

Workflow Engine

Memory Engine

Resource Engine

Monitoring Engine

Simulation Engine

Capability Engine

Lifecycle Engine

Interaction Engine

System services are stateless whenever possible.

---

# System Resources

Resources managed by AIOS.

Examples

CPU Budget

GPU Budget

Memory Budget

Context Window

Token Budget

Money Budget

Time Budget

Bandwidth

Storage

Workers request resources.

Resource Engine allocates them.

---

# Knowledge Objects

Persistent intellectual assets.

Examples

Knowledge Record

Experience Record

Skill Definition

Learning Pattern

Research Result

Reference Document

These objects survive indefinitely.

---

# Interaction Objects

Everything related to human interaction.

Examples

Conversation

Voice Session

Desktop Session

CLI Session

API Session

Notification

Interaction Context

Interaction objects are managed by the Interaction Engine.

---

# Infrastructure

Infrastructure enables the platform.

Examples

Sou

Academy

ACF

Security Kernel

Linux Kernel

Marketplace

SDK

Registry

Infrastructure supports all other categories.

---

# AIOS Object Hierarchy

```
AIObject

├── Actor
├── Mission
├── Organization
├── Worker
├── Runtime
├── Skill
├── Knowledge
├── Experience
├── Policy
├── Intent
├── Event
├── Engine
├── Resource
├── Interaction
└── Infrastructure
```

Every object inherits from AIObject.

---

# Object Ownership

Every object has one owner.

Examples

Mission
→ Organization

Worker
→ Supervisor

Skill
→ Academy

Knowledge
→ Academy

Policy
→ Security Kernel

Runtime
→ Runtime Layer

Engine
→ Execution Plane

Ownership is immutable unless explicitly transferred.

---

# Object Lifetime

Objects belong to one of three lifetimes.

Permanent

Examples

Knowledge

Experience

Skills

Organizations

Mission Templates

Policies

---

Semi-Permanent

Examples

Missions

Workflows

Benchmarks

Runtime Configurations

---

Temporary

Examples

Workers

Sessions

Messages

Voice Sessions

Execution Contexts

Temporary objects may be destroyed safely.

---

# Object Relationships

Objects communicate through defined relationships.

Mission

↓

Organization

↓

Supervisor

↓

Worker

↓

Runtime

↓

Engine

↓

Security Kernel

↓

Linux

Objects never bypass relationships.

---

# Dependency Rules

Lower layers never depend on higher layers.

Examples

Workers cannot control Sou.

Engines cannot modify Organizations.

Security Kernel cannot plan Missions.

Academy cannot execute code.

Every dependency is directional.

---

# AIOS Classification Rules

Every new feature introduced into AIOS MUST answer:

1. Which taxonomy category does it belong to?

2. Who owns it?

3. What is its lifetime?

4. What responsibilities does it have?

5. Which interfaces does it expose?

6. Which objects may communicate with it?

7. Which objects may not communicate with it?

If these questions cannot be answered, the feature is not ready for implementation.

---

# Final Statement

The taxonomy of AIOS is the foundation upon which every subsystem is built.

No object may exist outside this classification system.

Consistency of classification guarantees consistency of architecture.

Every future extension of AIOS must integrate into this taxonomy rather than creating parallel concepts.