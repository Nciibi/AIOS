# AIOS DNA
## Document 002 — Terminology

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | DNA |
| Document ID | AIOS-DNA-002 |
| Applies To | Entire AIOS Platform |

---

# Purpose

Language defines architecture.

Architecture defines software.

For a platform expected to evolve over decades and support hundreds of contributors, every technical term must have one precise meaning.

This document establishes the official vocabulary of AIOS.

Every RFC, specification, implementation, API, SDK, runtime, engine, organization, plugin, documentation page and research paper MUST use these definitions.

If two documents define the same concept differently, this document is authoritative.

---

# Terminology Rules

The following rules apply throughout AIOS.

• Every concept has exactly one canonical name.

• A concept must never have multiple meanings.

• Different concepts must never share the same name.

• Every AIObject belongs to one taxonomy category.

• Every document must use terminology exactly as defined here.

---

# Core Concepts

---

## AIOS

Classification

Platform

Definition

AIOS (Artificial Intelligence Operating System) is a software platform responsible for orchestrating autonomous intelligence.

AIOS does not replace Linux.

AIOS extends traditional operating systems by introducing a new abstraction layer dedicated to intelligent reasoning, organizational coordination, knowledge preservation, secure execution and continuous learning.

Responsibilities

• Orchestrate autonomous intelligence

• Coordinate organizations

• Govern missions

• Preserve knowledge

• Preserve experience

• Secure execution

• Enable runtime independence

Does Not

• Execute hardware directly

• Replace Linux

• Depend on a specific language model

---

## Mission

Classification

Strategic Object

Definition

A Mission is the highest-level unit of meaningful work inside AIOS.

Every human request, automation trigger or scheduled objective becomes exactly one Mission.

A Mission may require multiple organizations, workers, runtimes and execution stages.

Examples

• Build an application

• Design an FPGA

• Reverse engineer malware

• Trade a portfolio

• Moderate a Discord server

• Deploy Kubernetes

Created By

Sou

Owned By

Organization

Contains

Objectives

Constraints

Budget

Policies

Execution Graph

Workers

Outputs

Lifecycle

Created

↓

Planned

↓

Assigned

↓

Running

↓

Waiting

↓

Paused

↓

Completed

↓

Archived

Mission Rules

A Mission never executes itself.

A Mission never owns hardware.

A Mission always belongs to one Organization.

---

## Objective

Classification

Strategic Object

Definition

An Objective is an individual measurable outcome belonging to a Mission.

A Mission may contain multiple Objectives.

Example

Mission

↓

Create AIOS

Objectives

↓

Design Architecture

↓

Implement Kernel

↓

Create Documentation

↓

Run Tests

Objectives are atomic planning targets.

---

## Organization

Classification

Structural Object

Definition

A permanent organizational structure dedicated to one domain of expertise.

Organizations are long-lived.

Workers come and go.

Organizations remain.

Examples

Coding

Communication

Linux

Trading

Research

Robotics

FPGA

Embedded

Cybersecurity

Responsibilities

Planning

Governance

Resource ownership

Experience accumulation

Mission execution

Organization Structure

Director

↓

Managers

↓

Supervisors

↓

Workers

---

## Director

Classification

Structural Object

Definition

The highest authority inside an Organization.

Responsibilities

Mission Strategy

Resource Approval

Planning

Reporting to Sou

Never Performs

Direct execution.

---

## Manager

Classification

Structural Object

Definition

Coordinates multiple Supervisors.

Responsibilities

Planning

Scheduling

Resource Allocation

Progress Monitoring

---

## Supervisor

Classification

Structural Object

Definition

Coordinates Workers.

Responsibilities

Assign work

Monitor work

Review work

Restart failed workers

Spawn additional workers

---

## Worker

Classification

Execution Object

Definition

A temporary execution unit responsible for performing assigned work.

Workers are disposable.

Organizations are permanent.

Workers own no permanent knowledge.

Workers own no permanent experience.

Workers execute.

Nothing more.

Worker Lifetime

Created

↓

Initialized

↓

Running

↓

Blocked

↓

Paused

↓

Completed

↓

Destroyed

Workers Always Have

Context

Workspace

Runtime

Model

Capabilities

Session Memory

Health

Permissions

Workers Never Have

Permanent Knowledge

Permanent Experience

Strategic Authority

---

## Worker Template

Classification

Execution Object

Definition

A reusable blueprint used to create Worker Sessions.

Contains

Runtime Requirements

Capability Requirements

Policies

Workspace Rules

Prompt Stack

Skill Requirements

Environment Variables

Templates never execute.

---

## Worker Session

Classification

Execution Object

Definition

A live instance created from a Worker Template.

Contains

UUID

Runtime

Provider

Workspace

Memory

Health

Metrics

Budget

Logs

Lifecycle

Running

Paused

Restarting

Completed

Failed

Destroyed

---

# Intelligence Assets

---

## Skill

Classification

Intelligence Asset

Definition

A reusable package of expertise.

Skills are dynamically attached to Workers by the Academy.

A Skill may include

Knowledge

Examples

Prompt Fragments

Policies

Tools

Benchmarks

Validation Rules

Dependencies

Version

Signature

Example Skills

Rust

Git

Docker

FPGA

Nmap

Wireshark

OSINT

Trading

Linux

---

## Knowledge

Classification

Intelligence Asset

Definition

Verified reusable information.

Knowledge answers

"What is true?"

Knowledge survives forever.

Knowledge belongs to the Academy.

Knowledge never belongs to Workers.

---

## Experience

Classification

Intelligence Asset

Definition

Verified lessons extracted from completed Missions.

Experience answers

"What worked?"

Every Experience record must contain

Problem

Solution

Evidence

Confidence Score

Verification

Reusable Pattern

Only verified Experience becomes reusable.

---

## Memory

Classification

Execution Object

Definition

Temporary contextual information used during execution.

Memory answers

"What is happening right now?"

Memory expires.

Knowledge does not.

Experience does not.

Memory Levels

L1 Session Memory

L2 Organization Memory

L3 Global Memory

Archive

---

# AI Academy

Classification

Infrastructure

Definition

The permanent collective intelligence subsystem of AIOS.

Responsibilities

Store Skills

Store Knowledge

Store Experience

Store Mission Templates

Store Organization Templates

Store Policies

Store Benchmarks

Store Training Material

Academy Libraries

Skill Library

Knowledge Library

Experience Library

Prompt Library

Mission Library

Organization Library

Training Library

Policy Library

Workers receive assets from the Academy.

Workers never own them.

---

# Sou

Classification

Infrastructure

Definition

The strategic intelligence coordinator of AIOS.

Responsibilities

Reason

Plan

Recommend

Create Missions

Create Organizations

Spawn Workers

Allocate Resources

Monitor Progress

Optimize Execution

Sou Never

Executes commands

Touches Linux

Stores Knowledge

Bypasses Security

---

# Capability

Classification

Runtime Object

Definition

An abstract ability independent of implementation.

Examples

Reason

Code

Communicate

Trade

Search

Vision

Speech

Testing

Capability routing allows AIOS to remain runtime-independent.

---

## Runtime

Classification

Runtime Object

Definition

A concrete implementation capable of providing one or more Capabilities.

Examples

Claude Code

Codex

OpenClaw

OpenCode

Ollama

Gemini CLI

Browser Automation

Robotics Runtime

A Runtime is replaceable.

Capabilities are permanent.

---

# AI Communication Fabric (ACF)

Classification

Infrastructure

Definition

The universal communication infrastructure of AIOS.

Every subsystem communicates through ACF.

Communication Types

Commands

Queries

Events

Streams

Notifications

Broadcasts

Responsibilities

Routing

Delivery

Security

Encryption

Replay

Persistence

Observability

Distributed Communication

No component may bypass ACF.

---

## Intent

Classification

Trust Object

Definition

A requested action awaiting authorization.

Every execution begins as an Intent.

---

## Policy

Classification

Trust Object

Definition

A deterministic rule used by the Security Kernel to authorize or deny an Intent.

---

## Execution Plan

Classification

Trust Object

Definition

A verified execution strategy generated after policy evaluation and before execution.

Execution Plans are immutable once approved.

---

# AIOS Security Kernel

Classification

Infrastructure

Definition

The subsystem responsible for deterministic trust enforcement.

Pipeline

Intent

↓

Resolver

↓

Context

↓

Capabilities

↓

Policy

↓

Risk

↓

Execution Plan

↓

Execution

↓

Audit

Nothing bypasses the Security Kernel.

---

# Engine

Classification

System Service

Definition

A reusable operating-system service responsible for exactly one concern.

Examples

Planner Engine

Runtime Engine

Scheduler Engine

Simulation Engine

Workflow Engine

Identity Engine

Monitoring Engine

Each Engine has one responsibility.

---

# AIObject

Classification

Base Object

Definition

The universal base object inherited by every first-class entity inside AIOS.

Every AIObject contains

Immutable Identifier

Version

Lifecycle

Owner

Metadata

Relationships

Permissions

Audit History

Tags

No first-class object may exist outside AIObject.

---

# Reserved Terms

The following terms have fixed meanings inside AIOS.

Mission

Organization

Worker

Skill

Knowledge

Experience

Academy

Sou

Runtime

Capability

Engine

Intent

Policy

AIObject

ACF

Security Kernel

These terms must never be redefined.

---

# Final Statement

Language is architecture.

Every concept inside AIOS begins with terminology.

Consistent terminology produces consistent architecture.

Consistent architecture produces maintainable software.

This document is the authoritative vocabulary of AIOS and shall remain valid regardless of future implementations, programming languages, runtimes or models.