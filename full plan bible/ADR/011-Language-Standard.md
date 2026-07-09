# AIOS DNA
## Document 011 — Language Standard

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | DNA |
| Document ID | AIOS-DNA-011 |
| Applies To | Entire AIOS Platform |

---

# Purpose

Consistency is one of the defining characteristics of successful engineering projects.

Every subsystem, API, SDK, document, diagram, source file, plugin and community contribution should use a common language.

This document establishes the official language standard of AIOS.

If two terms describe the same concept, only one is considered correct.

---

# Guiding Principle

Every concept has exactly one official name.

Every official name has exactly one meaning.

No synonyms are used inside AIOS specifications.

---

# Canonical Terminology

The following names are mandatory throughout AIOS.

---

## AIOS

Correct

AIOS

Incorrect

AI Operating System

AI Operating Platform

Artificial OS

---

## Sou

Correct

Sou

Incorrect

Master Agent

Chief Agent

Coordinator

Supervisor AI

Manager AI

Sou is the official name.

---

## Academy

Correct

Academy

Incorrect

Knowledge Base

Memory System

Learning Engine

Brain

Database

The Academy is a subsystem.

Not merely storage.

---

## Organization

Correct

Organization

Incorrect

Team

Department

Squad

Crew

Group

Organizations are first-class architectural objects.

---

## Worker

Correct

Worker

Incorrect

Agent

Bot

Assistant

Executor

Worker is the official execution unit.

---

## Mission

Correct

Mission

Incorrect

Task

Job

Prompt

Request

Workflow

Tasks may exist internally.

The user interacts with Missions.

---

## Capability

Correct

Capability

Incorrect

Feature

Power

Function

Runtime Ability

Capabilities are runtime-independent.

---

## Runtime

Correct

Runtime

Incorrect

Provider

Model

Engine

Backend

Providers and models belong to a Runtime.

---

## Engine

Correct

Engine

Incorrect

Manager

Service

Module

Daemon

Engine refers only to reusable operating-system services.

---

## AI Communication Fabric

Correct

AI Communication Fabric

ACF

Incorrect

Message Bus

IPC Layer

Transport Layer

Communication Engine

ACF is infrastructure.

---

## Security Kernel

Correct

Security Kernel

Incorrect

Security Manager

Permission Engine

Security Service

Kernel Security

---

## AIObject

Correct

AIObject

Incorrect

Entity

Node

Resource

Item

Everything inherits from AIObject.

---

# Naming Rules

Object names should describe responsibility.

Not implementation.

Correct

Runtime Engine

Scheduler Engine

Identity Engine

Capability Engine

Incorrect

Main Engine

Manager Engine

Helper Engine

---

# Engine Naming

Every Engine should end with

Engine

Examples

Planner Engine

Workflow Engine

Simulation Engine

Runtime Engine

Knowledge Engine

---

# Organization Naming

Organizations use singular nouns.

Correct

Security

Coding

Research

Trading

Embedded

FPGA

Incorrect

Security Team

Developers

Researchers

Coders

---

# Worker Naming

Workers describe responsibility.

Correct

Backend Worker

Security Worker

Research Worker

Trading Worker

Incorrect

Claude Worker

GPT Worker

Codex Worker

Runtime names never appear in Worker names.

---

# Runtime Naming

Runtime names preserve their official product names.

Examples

Claude Code

Codex

OpenClaw

OpenCode

Ollama

Gemini CLI

DeepSeek

Future runtimes should retain their official names.

---

# Documentation Naming

Document names use

Title Case

Examples

Long-Term-Vision.md

Engineering-Goals.md

Language-Standard.md

Architectural-Principles.md

Avoid abbreviations where practical.

---

# Rust Naming

Rust code follows official Rust conventions.

Types

PascalCase

Functions

snake_case

Constants

SCREAMING_SNAKE_CASE

Traits

PascalCase

Modules

snake_case

---

# API Naming

REST endpoints should use nouns.

Correct

/missions

/workers

/organizations

/skills

Incorrect

/createMission

/doWork

/getSkills

HTTP methods describe actions.

---

# Event Naming

Events use past tense.

Examples

MissionCreated

WorkerStarted

KnowledgeAdded

MissionCompleted

RuntimeFailed

Events describe completed facts.

---

# Command Naming

Commands use imperative verbs.

Examples

CreateMission

PauseWorker

AttachSkill

AllocateRuntime

Commands request work.

They do not describe completed work.

---

# Query Naming

Queries describe information requests.

Examples

FindKnowledge

GetMissionStatus

ListWorkers

ResolveCapability

Queries never modify state.

---

# File Naming

Markdown

Title-Case.md

Rust Modules

snake_case.rs

Configuration

kebab-case.toml

Directories

snake_case/

Consistency is preferred over personal preference.

---

# Reserved Prefixes

Mission*

Worker*

Organization*

Runtime*

Engine*

Skill*

Knowledge*

Experience*

Policy*

Intent*

Capability*

These prefixes should not be reused for unrelated concepts.

---

# Abbreviations

Official abbreviations include

AIOS

ACF

IRS

SDK

API

RFC

ADR

Avoid creating new abbreviations unless necessary.

---

# Related Documents

AIOS-DNA-002 — Terminology

AIOS-DNA-003 — Taxonomy

AIOS-DNA-009 — Identity

AIOS-DNA-010 — Design Decisions

---

# Rationale

A shared language reduces ambiguity.

Reduced ambiguity improves communication.

Improved communication strengthens architecture.

Architecture survives through consistency.

---

# Future Extensions

Future subsystem specifications may introduce additional terminology.

New terms must remain compatible with this standard.

---

# Final Statement

The language used to describe AIOS is part of its architecture.

Consistency in language produces consistency in design.

Every contributor shares responsibility for preserving that consistency.