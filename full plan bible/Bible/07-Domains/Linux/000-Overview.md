# AIOS Bible â€” Domains
## Linux â€” 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-LNX-000 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Linux domain enables AIOS to manage, configure, secure, and monitor Linux systems â€” from single nodes to large fleets of servers. It provides the capability set for system administration, infrastructure automation, configuration management, performance tuning, troubleshooting, and compliance auditing across Linux distributions.

Linux system administration is a domain with high consequence: misconfiguration can cause outages, security breaches, or data loss. The Linux domain therefore emphasizes safety through capability bounds, dry-run verification, change approval workflows, and comprehensive evidence capture. Every command is verified before execution, and every change is reversible where possible.

## Domain Entities

The Linux domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| SysAdminWorker | A Worker specialized for Linux system administration | AGS: Linux/SysAdminWorker |
| InfraWorker | A Worker specialized for infrastructure-as-code management | AGS: Linux/InfraWorker |
| ComplianceWorker | A Worker specialized for compliance auditing and reporting | AGS: Linux/ComplianceWorker |
| InventorySnapshot | A knowledge artifact capturing system inventory | Academy: Knowledge |
| RunbookRecord | A knowledge artifact for automated runbook execution | Academy: Knowledge |

## Capabilities

The Linux domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| System Administration | `manage_users`, `configure_services`, `manage_packages`, `edit_config` | Low token, low compute |
| Infrastructure as Code | `write_ansible`, `write_terraform`, `write_dockerfile`, `manage_k8s` | Medium token, low compute |
| Monitoring | `check_health`, `analyze_logs`, `monitor_performance`, `set_up_alerts` | Low token, low compute |
| Security Hardening | `audit_ssh`, `configure_firewall`, `apply_cis_benchmark`, `check_selinux` | Medium token, low compute |
| Troubleshooting | `diagnose_failure`, `analyze_crash`, `debug_network`, `inspect_process` | Low token, medium compute |
| Backup & Recovery | `configure_backup`, `test_restore`, `manage_snapshots`, `dr_test` | Low token, variable I/O |
| Compliance | `run_cis_audit`, `check_pci_compliance`, `generate_report`, `remediate` | Medium token, low compute |

## Command Execution Safety

The Linux domain enforces a multi-stage verification pipeline for every command:

| Stage | Check | Enforced By |
|-------|-------|-------------|
| 1. Intent Validation | Command matches approved task | SysAdminWorker capabilities |
| 2. Scope Check | Target host is within authorized scope | Organization policy |
| 3. Dry Run | Preview of changes before execution | Playbook Manager (005) |
| 4. Permission Check | Worker has authorization for this operation | AZS |
| 5. Impact Analysis | Potential side effects assessed | DTS |
| 6. Rate Limit | Command frequency within policy | ROS budget |
| 7. Execution | Command sent with timeout and logging | Runtime |
| 8. Verification | Expected outcome confirmed | SysAdminWorker |
| 9. Evidence Capture | Full command, output, and outcome recorded | Academy Evidence Ingestor |

## Infrastructure Lifecycle

Linux infrastructure managed by AIOS follows this lifecycle:

```
Discovered â†’ Assessed â†’ Provisioned â†’ Configured â†’ Monitored â†’ Updated â†’ Decommissioned
```

| Phase | Description | Domain Activity |
|-------|-------------|-----------------|
| Discovered | New host detected or reported | Inventory scanning |
| Assessed | Baseline inventory and compliance captured | ComplianceWorker audit |
| Provisioned | OS installed, network configured | InfraWorker (Terraform) |
| Configured | Packages, services, users, security set | SysAdminWorker (Ansible) |
| Monitored | Health and performance tracking active | Monitoring capability |
| Updated | Patches, upgrades, configuration changes | SysAdminWorker |
| Decommissioned | Host retired, data migrated | InfraWorker |

## Invariants

1. **LNX-I-001 â€” Dry Run Before Apply**: Every configuration change must be previewed as a dry run before application. Direct apply without dry run is prohibited for all changes except emergency security patches.

2. **LNX-I-002 â€” Idempotent Operations**: All configuration management operations must be idempotent. Running the same playbook twice on the same host must produce identical state.

3. **LNX-I-003 â€” Scope-Bounded**: A SysAdminWorker operates only on hosts within its authorized scope. Cross-Organization host access is prohibited.

4. **LNX-I-004 â€” Change Authorization**: Destructive operations (service stop, package removal, firewall change) require specific authorization beyond standard admin rights.

5. **LNX-I-005 â€” Evidence per Change**: Every command and configuration change produces an Event capturing the full command, output, exit code, and authorization chain.

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Host unreachable during playbook execution | Playbook paused, retry with backoff (3 attempts). If still unreachable, host marked as offline, partial results reported. |
| Configuration drift detected between dry run and apply | Apply aborted. Drift report generated. Reassessment triggered before retry. |
| Package repository unavailable | Package operation queued. Alternative mirror checked. If all mirrors unavailable, operation fails with repository error. |
| Compliance scan finds critical violation | Immediate escalation to Security Council. Remediation playbook triggered automatically for known violations. |
| Reboot required after patch | Scheduled during maintenance window. If no window available, change deferred with alert. |

## Events

| LNX.EventType |      Produced When | Fields |
|-----------|--------------|--------|
| LNX.HostDiscovered |      New Linux host is found | host_id, hostname, distro, kernel_version, ip_address, discovered_by |
| LNX.CommandExecuted |      A command is run on a host | command_id, host_id, command, exit_code, duration, output_hash |
| LNX.ConfigChanged |      System configuration is modified | change_id, host_id, file_path, old_hash, new_hash, approved_by, playbook_id |
| LNX.PackageInstalled |      A package is installed or removed | package_id, host_id, action, package_name, version, repository |
| LNX.ComplianceScanRun |      Compliance audit completes | scan_id, host_id, standard, passed, failed, score, critical_findings |
| LNX.IncidentDetected |      Anomaly or alert is identified | incident_id, host_id, severity, category, details, recommended_action |
| LNX.PatchApplied |      Security patch is applied | patch_id, host_id, cve_list, reboot_required, outcome, duration_seconds |


## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Compliant |
| R2 - Dependency Order | Compliant |
| R3 - DRY | Compliant |
| R4 - Builder Pattern | Compliant |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Compliant |
| R10 - Simpler Over Complex | Compliant |
| R13 - Design for Failure | Compliant |
| R14 - Paved Path | Compliant |
| R15 - Open/Closed | Compliant |

## Cross-Cutting Concerns

### Security

Linux Workers operate under least-privilege access. Every command is authenticated via SSH keys or API tokens managed by ATS. Destructive operations (package removal, service stop, firewall changes) require explicit authorization from Security Council or delegated authority. All remote access is logged and auditable. (Physics/008-Security.md)

### Evidence

Every command, configuration change, and compliance scan produces an Event. The complete command history per host is stored in the Event Store. Configuration drift is detected by comparing current state against the last known-good snapshot. (PHI-008)

### Lifecycle

SysAdmin Workers follow the canonical Worker lifecycle. Infrastructure hosts follow the infrastructure lifecycle (Discovered â†’ Decommissioned). Configuration management runs follow a plan-apply-verify lifecycle. Compliance scans are periodic batch operations with their own job lifecycle. (Physics/006-Lifecycles.md)

### Capability Bounds

Linux capabilities are bounded by the authorized host scope, command whitelist, and resource budgets. A SysAdminWorker may only operate on hosts within its Organization's authorization scope. Destructive capabilities require elevated authorization. Command execution is bounded by timeout and rate limits. (Physics/007-Capabilities.md)

### Communication

All Linux domain communication flows through ACF. Remote host access uses SSH or API transport abstracted through resource providers. Playbooks and runbooks are distributed through ACF topics. Host discovery events broadcast through ACF for other systems to consume. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each Linux capability (admin, infra, compliance, monitoring) is a separate concern |
| R3 (DRY) | Infrastructure configuration is defined once in playbooks, not per-host |
| R4 (Builder) | Provisioning (InfraWorker) is separate from configuration (SysAdminWorker) |
| R9 (Deterministic) | Same playbook and inventory produces identical host state |
| R10 (Simpler Over Complex) | Infrastructure is declarative â€” desired state, not step-by-step scripts |
| R13 (Design for Failure) | Configuration changes are transactional â€” rollback on failure; commands have timeouts |

## Component Map

| Component | Document | Function |
|-----------|----------|----------|
| Configuration Manager | Linux/001-Config.md | Ansible playbook generation, config drift detection, state enforcement |
| Inventory Service | Linux/002-Inventory.md | Host discovery, asset tracking, software inventory, patch status |
| Compliance Engine | Linux/003-Compliance.md | CIS benchmark auditing, PCI-DSS checks, remediation automation |
| Monitoring Connector | Linux/004-Monitoring.md | Prometheus/Grafana integration, alert configuration, dashboard generation |

## Performance Characteristics

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Single command execution | < 2 seconds | 10 seconds |
| Playbook execution (10 tasks) | < 30 seconds | 2 minutes |
| Playbook execution (50 tasks) | < 5 minutes | 15 minutes |
| Configuration drift detection | < 10 seconds | 30 seconds |
| Compliance scan (single host) | < 1 minute | 5 minutes |
| Compliance scan (100 hosts) | < 10 minutes | 30 minutes |
| Patch application (single host) | < 2 minutes | 10 minutes |
| Host discovery scan (/24 subnet) | < 5 minutes | 15 minutes |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture â€” Linux domain structure |
| Physics/005-Events.md | Evidence â€” Linux operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” Linux capability bounds and command safety |
| Physics/010-Execution.md | Execution â€” Command execution model and verification pipeline |
| Bible/02-Core/Sou/002-Planner.md | Planner â€” Sou produces infrastructure plans |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” SysAdminWorker and ComplianceWorker Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” Inventory and runbook knowledge management |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” Change impact assessment |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” Compute budgets for monitoring and compliance |
| Bible/03-Institutions/Workers/005-Playbook-Manager.md | Playbook Manager â€” Automated runbook execution |
| Bible/04-Execution/Security/ATS/000-Auth-Methods.md | ATS â€” Host access authentication |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” SSH and API transport providers |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
