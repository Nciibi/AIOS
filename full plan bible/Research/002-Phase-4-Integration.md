# AIOS Research
## 002 — Phase 4: Linux & Ecosystem Integration

| Property | Value |
|----------|-------|
| Status | Draft |
| Version | 0.1 |
| Category | Research |
| Document ID | RESEARCH-002 |
| Source Laws | Law 3 — Law of Communication, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/009-Interaction.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Phase 4 integrates AIOS deeply into the Linux operating system. Since AIOS is a Linux distribution at its core, Sou should not merely orchestrate coding agents — it should orchestrate the entire OS. The core question: **How does Sou extend its executive intelligence to manage system services, hardware, and kernel-level operations?**

This document explores the research required for Sou to interact with the Linux kernel, system daemons, hardware devices, and system services, as well as the live dashboard that makes this orchestration visible to the user.

## Research Areas

### Area 1: Linux System Agent Architecture

Sou dispatches specialized workers for system-level operations, each with capability bounds scoped to specific OS subsystems.

**Proposed Agents:**

```
Sou
  │
  ├── Thermal Agent (monitors CPU/GPU temps, fan curves)
  ├── Power Agent (battery health, power profiles, sleep states)
  ├── Kernel Agent (module loading, sysctl tuning, kernel params)
  ├── Network Agent (WiFi, packet capture, DNS, routing)
  ├── Storage Agent (disk health, filesystem, mount points)
  ├── Process Agent (process monitoring, resource hogs, zombie cleanup)
  ├── GPU Agent (driver state, VRAM usage, compute scheduling)
  ├── Audio Agent (ALSA/PulseAudio/WirePlumber, device routing)
  ├── Display Agent (multi-monitor, resolution, Wayland/X11)
  └── Security Agent (auditd, SELinux/AppArmor, firewall)
```

Each agent is a Worker with capability bounds scoped to its subsystem. No agent can cross into another's domain without explicit authorization from Sou.

**Key Questions:**
- What is the privilege model for system-level agents? (Root? Capability-based? Namespaced?)
- How does Sou verify that a system agent isn't exceeding its OS-level authority?
- What is the sandbox for system agents? (Containers? cgroups? seccomp? All three?)
- How does Sou handle conflicting agents? (e.g., Power Agent vs. Performance Agent)

### Area 2: End-to-End System Diagnosis

Sou can diagnose and resolve system issues through multi-agent coordination.

**Example: Overheating Diagnosis**

```
User: "My laptop is overheating."
  │
  ▼
Sou receives via Conversation OS
  │
  ▼
Sou creates diagnostic mission:
  │
  ├── Thermal Agent:
  │   ├── Reads: /sys/class/thermal/thermal_zone*/temp
  │   ├── Reads: sensors output
  │   └── Reports: CPU 95°C, GPU 88°C, fan 6500 RPM
  │
  ├── Power Agent:
  │   ├── Reads: power supply status, governor settings
  │   ├── Reads: /sys/devices/system/cpu/cpu*/cpufreq/
  │   └── Reports: performance governor active, 45W power limit
  │
  ├── Process Agent:
  │   ├── Reads: top/htop data, /proc/*/stat
  │   ├── Reads: I/O stats, network connections
  │   └── Reports: chromium with 47 tabs consuming 60% CPU
  │
  ├── GPU Agent:
  │   ├── Reads: nvidia-smi (or equivalent)
  │   ├── Reads: GPU frequency, memory, utilization
  │   └── Reports: GPU idle (not the cause)
  │
  ▼
Sou correlates:
  ├── Root cause: Performance governor + high CPU load from Chromium
  ├── Recommendation: Switch to powersave governor, limit Chromium background tabs
  └── Action: Sou applies fix (if authorized) or presents to user
```

**Example: Network Troubleshooting**

```
User: "WiFi keeps dropping."
  │
  ▼
Network Agent:
  ├── iwconfig / nmcli diagnostics
  ├── Packet capture (tcpdump, 30s sample)
  ├── Ping test (gateway, DNS, internet)
  └── dmesg | grep -i wifi
  │
  ▼
Sou analyzes:
  ├── Signal: -72 dBm (marginal)
  ├── Errors: 12% packet loss
  ├── dmesg: "iwlwifi: Microcode SW error detected"
  └── Recommendation: Switch to 5GHz band, update iwlwifi firmware
```

**Key Questions:**
- How does Sou sequence multi-agent diagnostics? (Parallel for independent checks, sequential where dependencies exist)
- What is the authorization model for Sou applying system changes? (Always ask? L3+ can apply? User-configured policies?)
- How does Sou roll back changes that degrade system stability?
- How does Sou handle systems without root access? (Read-only diagnostics only)

### Area 3: Runtime-Integrated Workers

Workers that run not just AI model sessions, but system-level operations using the same tools as human operators.

**Worker Tool Categories:**

| Tool Category | Examples | Worker Type |
|--------------|----------|-------------|
| Network | nmap, wireshark, tcpdump, iperf | Network Agent |
| System | top, htop, iostat, vmstat, dmesg | System Agent |
| Storage | df, du, smartctl, lsblk | Storage Agent |
| Security | nmap, lynis, rkhunter, clamav | Security Agent |
| Development | git, cargo, npm, docker, make | Dev Workers |
| Browser | playwright, puppeteer, curl | Browser Agent |

**Key Questions:**
- How are system tools exposed to workers? (Via Tool System? Sandboxed? In containers?)
- What is the security model for granting a worker access to nmap vs. access to wireshark vs. both?
- How does Sou audit tool usage for system-level operations?
- Can users add custom tools to the Tool System? What is the certification process?

### Area 4: Live Dashboard (Visual Army)

A real-time visualization of Sou's orchestration activity — the "Visual Army" concept from the original design.

**Dashboard Components:**

```
╔══════════════════════════════════════════════════════════════╗
║                        SOU COMMAND CENTER                      ║
╠══════════════════════════════════════════════════════════════╣
║  System Health              │  Active Missions                ║
║  ┌────────────────────┐     │  ┌────────────────────┐        ║
║  │ CPU: ████████░░ 78% │     │  │ ● Messaging App   │        ║
║  │ RAM: ██████░░░░ 62% │     │  │ ● Security Scan   │        ║
║  │ GPU: ██░░░░░░░░ 18% │     │  │ ● Documentation   │        ║
║  │ TMP: 72°C          │     │  └────────────────────┘        ║
║  └────────────────────┘                                      ║
╠══════════════════════════════════════════════════════════════╣
║  Workers                    │  Model Usage                    ║
║  ┌────────────────────┐     │  ┌────────────────────┐        ║
║  │ ● Backend   (Run) │     │  │ Claude Opus  ██████ │        ║
║  │ ● UI       (Run) │     │  │ Claude Fable ██░░░░ │        ║
║  │ ● Crypto   (Run) │     │  │ GPT-5.5     ████░░ │        ║
║  │ ● QA       (Pau) │     │  │ Qwen 30B    ██░░░░ │        ║
║  │ ● Security (Run) │     │  │ Ollama      ░░░░░░ │        ║
║  └────────────────────┘     │  └────────────────────┘        ║
╠══════════════════════════════════════════════════════════════╣
║  Live Log Stream                                              ║
║  ┌────────────────────────────────────────────────────┐      ║
║  │ [14:32:01] Worker W-001: API endpoints complete  │      ║
║  │ [14:32:05] Worker W-004: UI mockups ready       │      ║
║  │ [14:32:12] Worker W-006: Security audit started │      ║
║  │ [14:32:18] Sou: Review requested for W-001      │      ║
║  └────────────────────────────────────────────────────┘      ║
╠══════════════════════════════════════════════════════════════╣
║  Cost Summary               │  Token Usage                   ║
║  ├── Session: $0.47        │  ├── Today: 287K tokens       ║
║  ├── Today:  $2.34        │  ├── This Mission: 143K       ║
║  └── Total:  $142.18      │  └── Budget Remaining: 57%    ║
╚══════════════════════════════════════════════════════════════╝
```

**Key Questions:**
- What data does the dashboard stream? (Events from ACF? Polling? WebSocket?)
- How does the dashboard handle 50+ concurrent workers? (Grouping? Filtering? Collapsing?)
- What interaction model? (Read-only monitoring? Can user intervene through dashboard?)
- How are security-sensitive operations displayed? (Redacted? Audited view?)

### Area 5: Ecosystem Integration Points

How Phase 4 connects AIOS to external services and platforms.

**Integration Targets:**

| Target | Protocol | Use Case |
|--------|----------|----------|
| Git providers | REST/SSH | Code synchronization, PR management |
| CI/CD systems | Webhook/API | Trigger builds on mission completion |
| Cloud providers | SDK | Provision resources on demand |
| Monitoring stack | Prometheus/OpenTelemetry | Export metrics, integrate dashboards |
| Notification | Webhook/SMTP/Apprise | Alert user on mission events |
| Package repos | Registry API | Publish worker outputs as packages |

## Open Questions

| Q-ID | Question | Priority |
|------|----------|----------|
| OQ-001 | What privilege model allows system agents to perform OS-level operations safely? | P0 |
| OQ-002 | How does Sou validate system agent outputs before taking action? | P0 |
| OQ-003 | What is the rollback mechanism for system-level changes? | P0 |
| OQ-004 | How does the dashboard handle real-time stream of 100+ concurrent workers? | P1 |
| OQ-005 | Can users create custom system agents? (e.g., monitoring a specific service) | P1 |
| OQ-006 | How does Sou interact with systemd? (Unit management, journal access) | P1 |
| OQ-007 | What is the security model for external integrations? (OAuth? API keys? mTLS?) | P1 |
| OQ-008 | How does Sou handle offline mode? (No network, local models only) | P2 |

## RFCs Needed

| RFC | Title | Description |
|-----|-------|-------------|
| RFC-INTG-001 | System Agent Framework | Privilege model, sandbox, tool access, audit for OS-level workers |
| RFC-INTG-002 | Sou Diagnostics Protocol | Multi-agent diagnostic sequencing, evidence correlation |
| RFC-INTG-003 | Live Dashboard Specification | Real-time data model, WebSocket protocol, rendering pipeline |
| RFC-INTG-004 | External Integration Gateway | Unified interface for Git, CI/CD, cloud, monitoring, notifications |

## Dependencies

| Dependency | Relationship |
|-----------|-------------|
| Bible/02-Core/Brain/Tools/000-Overview.md | Tool System — system tools need registration and sandboxing |
| Bible/02-Core/Brain/Conversation/000-Overview.md | Conversation OS — user-facing system reports |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime — system agents run on specialized runtimes |
| Bible/04-Execution/Security/000-Overview.md | Security Council — system agent authorization model |
| Bible/04-Execution/Security/Sandbox/000-Isolation.md | Sandbox — OS-level isolation for system agents |
| Bible/04-Execution/Security/Policy-System/000-PS.md | Policy System — system operation policies |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard — visualization infrastructure |
| Bible/08-Interfaces/API/000-Specifications.md | API — external integration interface |
| Bible/06-Services/ACF/000-Overview.md | ACF — all system agent communication |
| Bible/06-Services/ACF/005-Streaming.md | Streaming — real-time dashboard feed |
| Bible/05-Platform/000-LMS.md | LMS — system agent lifecycle |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/10-Research/000-Phases-2-5.md | Research roadmap — this file deepens Phase 4 |
| Bible/10-Research/002-Ecosystem.md | Ecosystem research — Phase 4 feeds the ecosystem |
| Bible/0007-Implementation-Roadmap.md | Implementation phasing — Phase 4 schedule |
| Bible/0008-Future-Research.md | Research agenda and open questions |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy System — L3+ agents can apply system changes |
| Bible/07-Domains/Linux/000-Overview.md | Linux Domain — AIOS Linux integration domain |
| ChatGPT-souuSouu Agent System Design.md | Original design vision — Visual Army, OS-level orchestration |
