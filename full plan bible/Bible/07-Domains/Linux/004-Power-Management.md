# AIOS Bible — Domains
## Linux — 004: Power Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-LNX-004 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Enable AIOS to manage Linux power states — suspend/resume, CPU frequency scaling, ACPI configuration, and thermal monitoring — to optimize energy consumption while preserving system stability.

## Architecture

Power management is modeled as a state machine with transitions between S0 (working), S1-S3 (sleep), S4 (hibernate), and S5 (power off). PowerProfiles bundle governor settings, wakeup sources, and timeout policies. The PowerManager agent reconciles desired profile against hardware capabilities. Thermal zones are monitored continuously; critical thresholds trigger alerts or automatic profile demotion. Suspend operations save running state, verify wakeup readiness, and emit events on completion.

### Architecture Flow

```text
┌─────────────────────────────────────────────────────────────────┐
│                      PowerManager Agent                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Governor  │  │ Suspend  │  │ Thermal  │  │ Wakeup   │        │
│  │ Handler   │  │ Handler  │  │ Handler  │  │ Handler  │        │
│  └─────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│        │             │             │             │              │
│  ┌─────▼─────────────▼─────────────▼─────────────▼─────┐       │
│  │              Profile & State Machine                  │       │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐  │       │
│  │  │ Power      │  │ S0-S5      │  │ Thermal       │  │       │
│  │  │ Profile    │  │ Transitions│  │ Thresholds    │  │       │
│  │  └────────────┘  └────────────┘  └───────────────┘  │       │
│  └───────────────────────┬──────────────────────────────┘       │
│                          │                                      │
│  ┌───────────────────────▼──────────────────────────────┐       │
│  │              Hardware / Kernel Interface              │       │
│  │  /sys/devices/system/cpu   /sys/class/thermal/       │       │
│  │  /sys/power/state          /proc/acpi/wakeup         │       │
│  └──────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model (TypeScript interfaces)

```typescript
interface PowerProfile {
  name: string;
  governor: CpuGovernor['governor'];
  scalingMinFreq: number;
  scalingMaxFreq: number;
  suspendTimeout: number;
  hibernateTimeout: number;
  wakeupSources: string[];
  thermalThrottle: 'passive' | 'active' | 'critical';
}

interface CpuGovernor {
  id: string;
  governor: 'performance' | 'powersave' | 'userspace' | 'ondemand' | 'conservative' | 'schedutil';
  minFrequency: number;
  maxFrequency: number;
  availableGovernors: string[];
}

interface ACPIState {
  state: 'S0' | 'S1' | 'S2' | 'S3' | 'S4' | 'S5';
  supported: boolean;
  wakeupCapable: boolean;
  wakeupDevices: string[];
}

interface ThermalZone {
  name: string;
  type: string;
  temperature: number;
  tripPoints: TripPoint[];
  cdevType: string;
  state: 'normal' | 'hot' | 'critical';
}

interface TripPoint {
  temperature: number;
  type: 'passive' | 'active' | 'hot' | 'critical';
  hysteresis: number;
  enabled: boolean;
}

interface WakeupSource {
  name: string;
  device: string;
  enabled: boolean;
  eventCount: number;
}

interface CpuBoostConfig {
  enabled: boolean;
  available: boolean;
  maxBoostFreq: number;
  cores: string[];
  state: 'boost' | 'noboost';
}

interface PlatformProfileConfig {
  name: string;
  platform: 'dell' | 'lenovo' | 'hp' | 'asus' | 'generic';
  profile: 'balanced' | 'performance' | 'quiet' | 'cool';
  availableProfiles: string[];
  state: 'active' | 'inactive';
}

interface PowerAuditEntry {
  id: string;
  timestamp: string;
  profileSnapshot: PowerProfile;
  governorStates: CpuGovernor[];
  acpiStates: ACPIState[];
  thermalReadings: ThermalZone[];
  wakeupSources: WakeupSource[];
  duration: number;
}
```

## Core Concepts / Operations

- **set_power_profile(profile)** — applies named power profile across all CPUs and devices
- **switch_governor(id, governor)** — changes CPU frequency scaling governor
- **configure_suspend(config)** — sets suspend/hibernate timeouts and wakeup sources
- **initiate_suspend(mode)** — triggers S3 suspend or S4 hibernate with pre-save checks
- **initiate_resume()** — triggers resume from suspend or hibernate
- **manage_thermal(zone, action)** — sets thermal trip points or enables cooling device
- **list_wakeup_sources()** — enumerates devices that can wake the system

### Operations Table

| Operation | Description | Preconditions | Postconditions |
|-----------|-------------|---------------|----------------|
| set_power_profile | Applies named power profile across CPUs and devices | Profile exists in PowerProfile store; governor available | Profile active; CPUs scaled; timeouts and wakeup configured |
| switch_governor | Changes CPU frequency scaling governor | Governor available on CPU hardware; cpufreq driver loaded | Governor switch applied; scaling range preserved |
| configure_suspend | Sets suspend/hibernate timeouts and wakeup sources | ACPI S3/S4 supported; wakeup devices valid | Timeouts written to sleep config; wakeup devices configured |
| initiate_suspend | Triggers S3 suspend or S4 hibernate with pre-save checks | No critical thermal event active; state serialized | System suspended/hibernated; saved state ref recorded |
| initiate_resume | Triggers resume from suspend or hibernate | Wakeup event received; saved state intact | System resumed; drivers reinitialized; resume event emitted |
| manage_thermal | Sets thermal trip points or enables cooling device | Thermal zone exists; cooling device available | Trip points updated; cooling device enabled/disabled |
| list_wakeup_sources | Enumerates devices that can wake the system | /proc/acpi/wakeup accessible | Wakeup device list returned; no state change |
| set_cpu_boost | Enables or disables CPU boost/turbo mode | CPU supports boost; intel_pstate/amd-pstate driver loaded | Boost mode toggled; max frequency adjusted accordingly |
| configure_platform_profile | Sets OEM platform profile (balanced/performance/cool) | Platform firmware supports profile; platform driver loaded | Platform profile applied; thermal and power characteristics changed |
| set_rtc_wakealarm | Schedules RTC wake alarm for next boot | RTC device present; /sys/class/rtc accessible | Wakealarm set; system will wake at specified time |
| audit_power_state | Captures full power state snapshot for diagnostics | Power subsystems accessible; sufficient permissions | Power state snapshot written to audit store; no state change |

## Internal Interfaces (table)

| Interface | Provider | Consumer | Purpose |
|-----------|----------|----------|---------|
| IPowerProfileManager | ProfileHandler | PowerManager | Apply power profiles |
| ICpuGovernorManager | GovernorHandler | PowerManager | Switch CPU governor |
| ISuspendManager | SuspendHandler | PowerManager | Initiate suspend/resume |
| IThermalManager | ThermalHandler | PowerManager | Monitor and manage thermal zones |
| IWakeupManager | WakeupHandler | PowerManager | Configure wakeup sources |
| ICpuBoostManager | CpuBoostHandler | PowerManager | Control CPU boost/turbo mode |
| IPlatformProfileManager | PlatformProfileHandler | PowerManager | Set OEM platform profiles |
| IPowerAuditor | PowerAuditor | PowerManager | Capture and report power state snapshots |

## Events (table)

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| Linux.PowerProfileChanged | ProfileHandler applies a new power profile | profileName, governor, previousProfile, appliedAt |
| Linux.SuspendInitiated | SuspendHandler starts the suspend sequence | mode, savedStateRef, processesFrozen, startedAt |
| Linux.ResumeCompleted | SuspendHandler reports successful resume | mode, duration, wakeupSource, resumedAt |
| Linux.ResumeFailed | SuspendHandler reports resume failure | mode, error, partialState, recoveryAction |
| Linux.ThermalEvent | ThermalHandler crosses a thermal threshold | zoneName, temperature, state, threshold, trending |
| Linux.GovernorChanged | GovernorHandler switches CPU frequency governor | governor, cpuCores, previousGovernor, changedBy |
| Linux.WakeupSourceChanged | WakeupHandler enables or disables a wakeup source | device, enabled, acpiName, powerState |

## Error Cases (table with Code, Condition, Severity, Recovery)

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| PWR-001 | Power state S3/S4 not supported by hardware | Error | Fall back to supported state, log capabilities |
| PWR-002 | CPU governor not available on this hardware | Warning | Fall back to nearest available governor |
| PWR-003 | Resume from suspend failed (driver timeout) | Critical | Force reboot, collect crash dump |
| PWR-004 | Thermal zone at critical temperature | Critical | Trigger emergency shutdown or profile demotion |
| PWR-005 | Wakeup device not found or not supported | Warning | Log, skip unsupported wakeup configuration |
| PWR-006 | Suspend blocked by active process | Error | Log blocking process list, abort suspend |
| PWR-007 | Frequency scaling driver not loaded | Warning | Load driver module or fall back to acpi-cpufreq |

## Invariants (table with ID, Rule, Enforcement)

| ID | Rule | Enforcement |
|----|------|-------------|
| PWR-INV-01 | Suspend saves running state before powering down | SuspendHandler verifies state serialization before S3/S4 |
| PWR-INV-02 | Wakeup readiness is verified after suspend config | SuspendHandler tests wakeup device before confirming config |
| PWR-INV-03 | CPU frequency never exceeds hardware max | GovernorHandler clamps scaling to hardware capabilities |
| PWR-INV-04 | Thermal trip points are monotonically increasing | ThermalHandler validates trip point ordering on config |
| PWR-INV-05 | Power profile changes are reverted on failure | ProfileHandler rolls back to previous profile if apply fails |
| PWR-INV-06 | Suspend is not initiated while critical thermal event active | PowerManager blocks suspend when thermal state is critical |

## Design DNA (table with Rule, Assessment — include R1,R2,R3,R4,R5,R6,R9,R10,R13,R14,R15)

| Rule | Assessment |
|------|------------|
| R1 — Composition over Inheritance | PowerProfile composes governor, thermal, and wakeup settings; agent composes handlers |
| R2 — Explicit over Implicit | All power states and governors explicitly declared; no automatic fallback without log |
| R3 — Immutable Artifacts | Saved suspend state is immutable snapshot; power profiles versioned |
| R4 — Stateless Workers | PowerManager is stateless; state held in PowerProfile resources |
| R5 — Idempotency | Applying same power profile twice is no-op; governor switch idempotent |
| R6 — Observability | Every power state transition and thermal event emits structured event |
| R9 — Fail Closed | On resume failure, system halts to safe recovery state; no partial boot |
| R10 — Least Privilege | Suspend and governor changes require elevated capability grants |
| R13 — Graceful Degradation | If preferred governor unsupported, fall back to nearest alternative |
| R14 — Data Immutability | Power profile history preserved; previous profile snapshots retained |
| R15 — Explicit Errors | Every failure returns typed code with recovery action |

## Related Documents (table)

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Linux/000-Overview.md | Parent overview |
| Bible/07-Domains/Linux/001-Kernel.md | Kernel parameters for CPU scaling and ACPI |
| Bible/07-Domains/Linux/002-System-Admin.md | System administration sibling |
| Bible/07-Laws/Law-004-Evidence.md | Audit trail for power events |
| Bible/07-Laws/Law-007-Capability-Bounds.md | Capability scoping for power ops |
| Bible/Physics/005-Events.md | Event schema lineage |
| Bible/Physics/007-Capabilities.md | Capability model |
| Bible/Physics/010-Execution.md | Execution lifecycle |
