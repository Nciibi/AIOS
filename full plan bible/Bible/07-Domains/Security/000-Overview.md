# AIOS Bible â€” Domains
## Security â€” 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-SEC-000 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds, Law 8 â€” Law of Verification-First |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Security domain enables AIOS to perform security operations â€” vulnerability assessment, penetration testing, threat detection, incident response, security monitoring, and compliance auditing. It provides the capability set for proactive security analysis and reactive incident handling across all AIOS domains and infrastructure.

Security is a cross-cutting domain with unique constraints. Unlike other domains where the goal is to produce artifacts or complete tasks, Security's goal is to identify risk, prevent harm, and maintain constitutional compliance. Security operations follow a verification-first approach (Law 8): every finding is verified, every exploit is confirmed in a safe environment before reporting, and every remediation is tested before deployment.

## Domain Entities

The Security domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| SecurityWorker | A Worker specialized for security operations | AGS: Security/SecurityWorker |
| PenTestWorker | A Worker for authorized penetration testing | AGS: Security/PenTestWorker |
| ThreatAnalyst | A Worker for threat intelligence and analysis | AGS: Security/ThreatAnalyst |
| IncidentResponder | A Worker for incident response coordination | AGS: Security/IncidentResponder |
| VulnerabilityReport | A knowledge artifact for a verified vulnerability | Academy: Knowledge |
| ThreatIntel | A knowledge artifact for threat intelligence data | Academy: Knowledge |

## Capabilities

The Security domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Vulnerability Assessment | `scan_vulnerabilities`, `analyze_cve`, `assess_risk`, `prioritize_findings` | Low token, medium compute |
| Penetration Testing | `reconnaissance`, `exploit_verify`, `privilege_escalation`, `lateral_movement` | Medium token, low compute (isolated) |
| Threat Detection | `analyze_logs`, `detect_anomaly`, `correlate_events`, `hunt_threats` | Low token, high compute |
| Incident Response | `contain_incident`, `eradicate_threat`, `recover_services`, `document_lessons` | Medium token, low compute |
| Security Monitoring | `monitor_endpoints`, `analyze_network`, `detect_intrusion`, `alert_triage` | Low token, medium compute |
| Compliance Auditing | `audit_configuration`, `check_standard`, `generate_evidence`, `report_findings` | Medium token, low compute |
| Threat Intelligence | `collect_ioc`, `analyze_tactics`, `track_actors`, `produce_intel` | High token, low compute |

## Verification-First Security Operations

All Security domain operations comply with Law 8 (Verification-First). No action with security impact is performed without prior verification:

| Phase | Description | Verification Step |
|-------|-------------|-------------------|
| Reconnaissance | Gather information about target | Verify information sources are authorized |
| Analysis | Identify potential vulnerabilities | Verify findings in sandbox before reporting |
| Exploit Verification | Confirm a vulnerability is real | Verify in isolated environment â€” never on production |
| Reporting | Document findings | Verify findings against evidence before publication |
| Remediation | Fix the vulnerability | Verify fix in test environment before deployment |
| Re-testing | Confirm remediation effectiveness | Verify the same test passes after fix |

A Security Worker that identifies a potential vulnerability must first reproduce and verify it in a sandbox before creating a VulnerabilityReport. Reports may not be based on unverified findings.

## Incident Response Lifecycle

Security incidents follow the NIST-based lifecycle:

```
Preparation â†’ Detection â†’ Analysis â†’ Containment â†’ Eradication â†’ Recovery â†’ Post-Mortem
```

| Phase | Description | Domain Activity |
|-------|-------------|-----------------|
| Preparation | Tools, playbooks, communication plans ready | Playbook Manager (Workers/005) |
| Detection | Anomaly or alert triggers investigation | ThreatDetector capability |
| Analysis | Scope, impact, root cause determined | ThreatAnalyst Worker |
| Containment | Isolate affected systems, stop spread | IncidentResponder Worker |
| Eradication | Remove threat, patch vulnerability | PenTestWorker + SysAdminWorker |
| Recovery | Restore normal operations, verify | IncidentResponder Worker |
| Post-Mortem | Lessons learned, evidence preserved | Knowledge artifact produced |

## Invariants

1. **SEC-I-001 â€” Verify Before Report**: No vulnerability may be reported without being verified in a sandbox environment. Unverified findings are provisional only and must be clearly marked as such.

2. **SEC-I-002 â€” Least Privilege**: Security Workers operate with the minimum permissions necessary for their assigned task. Penetration testing capabilities are tightly scoped and time-limited.

3. **SEC-I-003 â€” No Production Exploitation**: Exploit verification must occur exclusively in sandbox or test environments. Production exploitation is prohibited regardless of authorization level.

4. **SEC-I-004 â€” Chain of Evidence**: Every security operation produces an immutable evidence chain. The complete investigation trail â€” from initial finding through verification through remediation â€” must be preserved.

5. **SEC-I-005 â€” Escalation on Certainty**: Verified critical vulnerabilities must be escalated to the Security Council within 15 minutes of verification. Delayed escalation is a constitutional violation.

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Vulnerability found in AIOS core system | Critical severity. Immediate escalation to Security Council. Core team paged. System may be isolated. |
| Penetration test inadvertently affects production | Test immediately halted. Incident response triggered. Full forensic analysis conducted. |
| Threat intelligence conflicts with current assessment | Conflicting intel evaluated by ThreatAnalyst. Confidence scores compared. Higher-confidence intel takes precedence. |
| Compliance audit fails on critical control | Automated remediation triggered if available. Security Council notified. Manual remediation planned. |
| Incident responder cannot contain within SLO | Escalation to Security Council. Broader containment authority requested. System isolation if needed. |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Security.VulnerabilityFound` | Potential vulnerability identified | finding_id, target, cve, cvss_score, confidence, discovery_method |
| `Security.VulnerabilityVerified` | Vulnerability confirmed in sandbox | finding_id, verification_env, exploit_result, risk_level, reproducibility |
| `Security.ExploitAttempted` | Exploit verification executed | attempt_id, target_sandbox, technique, outcome, detection_bypassed |
| `Security.IncidentDetected` | Security incident is identified | incident_id, severity, category, affected_assets, confidence |
| `Security.IncidentContained` | Incident containment completed | incident_id, containment_action, effectiveness, duration_seconds |
| `Security.IncidentResolved` | Incident fully resolved | incident_id, recovery_action, post_mortem_ref, lessons_learned |
| `Security.IntelReportGenerated` | Threat intelligence report produced | report_id, threat_actor, ttps, iocs, confidence, tlp_level |
| `Security.ComplianceAuditRun` | Compliance audit completes | audit_id, standard, scope, passed, failed, score, critical_findings |

## Cross-Cutting Concerns

### Security

The Security domain is itself governed by security controls. Security Workers operate under the principle of least privilege â€” a PenTestWorker may execute exploits only in designated sandbox environments. All Security domain operations are logged to the Security Council. No Security Worker may override security controls without authorization. (Physics/008-Security.md)

### Evidence

Evidence is the foundation of all Security domain operations. Every scan, test, verification, and response action produces an Event. Vulnerability reports include the full evidence chain from initial finding through verification. Incident response produces a complete evidence record for post-mortem analysis. (PHI-008)

### Lifecycle

Security Workers follow the canonical Worker lifecycle. Vulnerability findings follow a lifecycle: Found â†’ Verified â†’ Reported â†’ Triaged â†’ Fixed â†’ Re-tested â†’ Closed. Incidents follow the IR lifecycle. Threat intelligence follows the Academy knowledge lifecycle. (Physics/006-Lifecycles.md)

### Capability Bounds

Security capabilities are tightly bounded. No Security Worker may execute exploits outside authorized sandbox environments. Penetration testing requires explicit authorization from Security Council for each target scope. Incident responders operate within pre-approved playbooks â€” novel response actions require authorization. (Physics/007-Capabilities.md)

### Communication

All Security domain communication flows through ACF with high-priority classification. Security events are broadcast on high-priority ACF topics with guaranteed delivery. Incident notifications bypass normal routing and are delivered directly to the Security Council. Threat intelligence is distributed through restricted Academy channels. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each security capability (assessment, pentest, detection, IR, monitoring, audit) is separate |
| R4 (Builder) | Vulnerability finding (discovery) is separate from verification (sandbox) |
| R7 (Testability) | Every security finding must be reproducible in a test environment |
| R8 (Single Source) | All vulnerability data is normalized to a single finding schema |
| R9 (Deterministic) | Same target and toolset produces identical scan results |
| R13 (Design for Failure) | Security operations fail closed â€” deny on uncertainty, preserve evidence |

## Component Map

| Component | Document | Function |
|-----------|----------|----------|
| Vulnerability Scanner | Security/001-VulnScan.md | CVE scanning, dependency checking, configuration auditing |
| Penetration Testing Engine | Security/002-Pentest.md | Automated recon, exploit verification, privilege escalation testing |
| Incident Response Manager | Security/003-IR.md | Incident detection, containment orchestration, evidence preservation |
| Threat Intelligence Feeder | Security/004-ThreatIntel.md | IOC collection, TTP analysis, threat actor tracking, intel distribution |
| Compliance Auditor | Security/005-Compliance.md | Regulatory standard checks, evidence collection, report generation |

## Performance Characteristics

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Vulnerability scan (single host) | < 2 minutes | 10 minutes |
| Vulnerability scan (network /24) | < 15 minutes | 60 minutes |
| Exploit verification (sandbox) | < 5 minutes | 30 minutes |
| Incident detection to alert | < 30 seconds | 2 minutes |
| Incident containment | < 15 minutes | 60 minutes |
| Compliance audit (single standard) | < 10 minutes | 30 minutes |
| Threat intel report generation | < 30 minutes | 2 hours |
| Escalation of critical finding | < 5 minutes | 15 minutes |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture â€” Security domain structure |
| Physics/005-Events.md | Evidence â€” Security operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” Security capability bounds and verification-first approach |
| Physics/008-Security.md | Security â€” Security domain implements AIOS security model |
| Bible/01-Governance/002-DGP.md | DGP â€” Security-related decision routing |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning â€” Security findings inform Sou's risk assessment |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” SecurityWorker and PenTestWorker Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” Vulnerability and threat intelligence knowledge management |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” Risk assessment for vulnerability prioritization |
| Bible/04-Execution/Security/000-Overview.md | Execution Security â€” Runtime security enforcement |
| Bible/04-Execution/Security/IDS/000-Overview.md | IDS â€” Identity integrity verification |
| Bible/04-Execution/Security/ATS/000-Auth-Methods.md | ATS â€” Authentication security analysis |
| Bible/04-Execution/Security/Audit/000-EAS.md | Audit â€” Evidence Audit Service integration |
| Bible/04-Execution/Security/IDS/000-Overview.md | IDS â€” Identity integrity verification |
| Bible/08-Interfaces/SDK/001-Audit-SDK.md | Audit SDK â€” Security evidence audit integration |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
