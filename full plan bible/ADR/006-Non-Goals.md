# AIOS DNA
## Document 006 — Non-Goals

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | DNA |
| Document ID | AIOS-DNA-006 |
| Applies To | Entire AIOS Platform |

---

# Purpose

Defining what AIOS will not become is as important as defining what it will become.

Every successful operating system establishes clear boundaries.

These boundaries prevent architectural drift, unnecessary complexity, feature creep and conflicting responsibilities.

This document defines those boundaries.

---

# Principle

Whenever a proposed feature conflicts with this document, the feature should be rejected, redesigned or implemented outside AIOS.

---

# AIOS Will Not Become Another Chatbot

AIOS is not designed to compete with conversational assistants.

Conversation is only one interaction method.

The purpose of AIOS is orchestration.

Not conversation.

---

# AIOS Will Not Replace Linux

Linux remains responsible for

• Memory

• CPU Scheduling

• Networking

• Drivers

• Filesystems

• Processes

• Hardware

AIOS extends Linux.

It does not replace it.

---

# AIOS Will Not Depend On Any AI Provider

AIOS must remain provider neutral.

No architecture may require

OpenAI

Anthropic

Google

DeepSeek

OpenRouter

or any future provider.

Providers are implementations.

Not architecture.

---

# AIOS Will Not Depend On A Specific Model

No model is permanent.

Models evolve continuously.

AIOS must survive replacement of every language model without architectural changes.

---

# AIOS Will Not Hardcode Runtime Logic

Business logic shall never depend upon

Claude Code

Codex

OpenClaw

Gemini

Ollama

or future runtimes.

Everything routes through Capabilities.

---

# AIOS Will Not Store Permanent Knowledge Inside Workers

Workers are temporary.

Knowledge is permanent.

Workers consume knowledge.

They never own it.

---

# AIOS Will Not Store Experience In Conversations

Conversation history is not experience.

Experience requires

Verification

Confidence

Evidence

Pattern extraction

Only then may it enter the Academy.

---

# AIOS Will Not Execute Unverified Actions

Every action must pass through

Intent

↓

Resolver

↓

Policy

↓

Execution Plan

↓

Execution

Nothing bypasses the Security Kernel.

---

# AIOS Will Not Mix Responsibilities

Sou reasons.

Workers execute.

Academy teaches.

ACF communicates.

Kernel secures.

Linux executes system calls.

Responsibilities remain isolated.

---

# AIOS Will Not Duplicate Intelligence

Knowledge should exist once.

Skills should exist once.

Experience should exist once.

Organizations should reference shared assets rather than duplicate them.

---

# AIOS Will Not Hide Decisions

Major decisions should always be explainable.

Users should understand

why

not only

what.

---

# AIOS Will Not Require Internet Connectivity

Internet access is optional.

Core AIOS functionality should operate offline whenever local resources are available.

Cloud services enhance AIOS.

They do not define AIOS.

---

# AIOS Will Not Assume Unlimited Resources

AIOS should function across a wide range of environments.

Examples include

Personal laptops

Developer workstations

Edge devices

Home servers

Cloud clusters

Architectural assumptions should remain resource aware.

---

# AIOS Will Not Lock Users Into One Workflow

Users may interact through

CLI

GUI

Voice

API

Mobile

Browser

Remote clients

Interaction methods are interchangeable.

---

# AIOS Will Not Prevent Future Evolution

Architecture should evolve.

Implementation should evolve.

Skills should evolve.

Organizations should evolve.

The DNA remains stable.

---

# AIOS Will Not Become Monolithic

Subsystems should remain independently replaceable.

Examples

Academy

Sou

ACF

Security Kernel

Runtime Layer

Organizations

Interaction Engine

No subsystem should require rewriting the entire platform.

---

# AIOS Will Not Sacrifice Security For Convenience

Convenience should never bypass

Policies

Capabilities

Verification

Auditing

Security remains mandatory.

---

# AIOS Will Not Learn Automatically Without Verification

Not every observation becomes knowledge.

Not every solution becomes experience.

Every permanent learning artifact requires validation before entering the Academy.

---

# AIOS Will Not Treat Workers As Permanent Entities

Workers are execution resources.

Organizations preserve identity.

The Academy preserves intelligence.

Workers disappear after work completes.

---

# AIOS Will Not Assume Single Machine Execution

Every subsystem should remain compatible with future distributed execution.

Single-node operation is the default.

Distributed operation is a long-term capability.

---

# Final Statement

Great software is defined as much by what it refuses to become as by what it achieves.

The purpose of these non-goals is to preserve the identity, simplicity and longevity of AIOS.

Any future proposal conflicting with these principles should be reconsidered before implementation.