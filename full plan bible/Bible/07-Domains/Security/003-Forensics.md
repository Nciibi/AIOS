# AIOS Bible — Domains
## Security — 003: Forensics

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-SEC-003 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Digital Forensics provides the engine for forensic investigation within AIOS — evidence acquisition, disk imaging, memory analysis, log correlation, timeline reconstruction, and chain of custody management. It is the evidentiary backbone of the Security domain, enabling IncidentResponders and ThreatAnalysts to conduct post-incident investigations with legally admissible evidence.

Every forensic operation follows Law 4 (Evidence) and the immutable chain of custody principle. Evidence is acquired using write-protected methods, cryptographically hashed at acquisition time, and stored in tamper-evident storage. Every transfer, analysis, and access event is logged to the chain of custody record.

The forensic engine supports multiple evidence types: disk images (raw, EWF, AFF), memory dumps (full, proc-only, kernel), log collections (syslog, auditd, Windows Event, custom), and network captures (PCAP, PCAPNG). Each evidence type has a dedicated acquisition and analysis pipeline with preservation guarantees.

## Architecture

```
 +------------------+     +------------------+     +------------------+
 |  Acquisition      | --> |  Preservation     | --> |  Analysis         |
 |  Write-protected  |     |  Hash verification |    |  Memory parsing  |
 |  Imaging tools    |     |  Tamper sealing   |    |  Disk forensics  |
 |  Capture engines  |     |  Storage locking  |    |  Log correlation |
 +------------------+     +------------------+     +------------------+
                                                          |
                                                          v
 +------------------+     +------------------+     +------------------+
 |  Evidence Sealing | <-- |  Reporting        | <-- |  Reconstruction  |
 |  Cryptographic    |     |  Report generate  |     |  Timeline build  |
 |  Seal finalize    |     |  Evidence catalog |     |  Event mapping   |
 |  Archive commit   |     |  Expert summary   |     |  Root cause      |
 +------------------+     +------------------+     +------------------+
```

The pipeline acquires evidence from source systems using write-blocked hardware or software methods. Preservation computes SHA-256 hashes, seals evidence in tamper-evident storage, and initializes the chain of custody. Analysis parses memory, disk, logs, and network captures for artifacts. Reconstruction correlates artifacts into a chronological timeline with event mapping. Reporting produces the forensic case report with full evidence catalog. Evidence sealing cryptographically finalizes the case for archival.

## Data Model

```typescript
interface ForensicCase {
  caseId: string;
  incidentRef: string;
  title: string;
  status: CaseStatus;
  evidenceItems: EvidenceItem[];
  timeline: TimelineEvent[];
  chainOfCustody: ChainOfCustodyEntry[];
  analysisResults: AnalysisResult[];
  openedAt: number;
  closedAt?: number;
  sealedBy?: string;
  sealHash?: string;
}

interface EvidenceItem {
  evidenceId: string;
  type: EvidenceType;
  source: string;
  acquisitionMethod: string;
  acquisitionCommand: string;
  acquisitionHash: string;
  hashAlgorithm: string;
  hashVerified: boolean;
  sizeBytes: number;
  storagePath: string;
  acquiredAt: number;
  acquiredBy: string;
  chainOfCustody: ChainOfCustodyEntry[];
  status: 'acquired' | 'preserved' | 'analyzing' | 'completed' | 'sealed';
}

type EvidenceType = 'disk_image' | 'memory_dump' | 'log_collection' | 'pcap' | 'file_artifact' | 'registry_hive';

interface DiskImage {
  evidenceId: string;
  format: 'raw' | 'ewf' | 'aff' | 'vmdk' | 'vhdx';
  sectorSize: number;
  totalSectors: number;
  partitionTable: PartitionEntry[];
  writeBlockerRef: string;
  verifiedCopy: boolean;
}

interface MemoryDump {
  evidenceId: string;
  dumpType: 'full' | 'kernel' | 'process' | 'suspended';
  osVersion: string;
  kernelBase: number;
  processList: ProcessEntry[];
  dumpTool: string;
  compressionMethod: string;
}

interface TimelineEvent {
  eventId: string;
  timestamp: number;
  sourceEvidenceId: string;
  eventType: string;
  description: string;
  artifacts: string[];
  confidence: number;
  correlatedWith: string[];
}

interface ChainOfCustodyEntry {
  sequence: number;
  action: 'acquire' | 'transfer' | 'analyze' | 'copy' | 'seal' | 'release';
  actorId: string;
  timestamp: number;
  notes: string;
  previousHash: string;
  currentHash: string;
  signature: string;
}

interface AnalysisResult {
  analysisId: string;
  evidenceId: string;
  analyzerType: 'memory' | 'disk' | 'log' | 'network' | 'artifact';
  findings: string[];
  iocs: string[];
  artifactsFound: number;
  confidence: number;
  completedAt: number;
}

type CaseStatus = 'open' | 'analyzing' | 'completed' | 'sealed' | 'reopened';
```

## Core Concepts / Operations

| Operation | Preconditions | Postconditions |
|-----------|--------------|----------------|
| acquire_evidence | Source system accessible, write-blocker engaged | Evidence acquired, hash computed, chain initialized |
| create_image | Source disk connected, imaging tool ready | Disk image created, hash verified, integrity confirmed |
| analyze_memory | Memory dump acquired, OS profile identified | Processes, network connections, loaded modules extracted |
| reconstruct_timeline | Multiple evidence items analyzed | Correlated timeline with event ordering and confidence |
| seal_evidence | All analysis complete, case ready for archive | Evidence sealed, final hash computed, case locked |
| verify_chain_of_custody | Chain of custody entries present | All hashes verified, no gaps or tampering detected |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| IEvidenceAcquisition | Forensics | IncidentResponder, ThreatAnalyst | ACF sync |
| IImageProcessor | Forensics | IEvidenceAcquisition | Internal |
| IMemoryAnalyzer | Forensics | IncidentResponder | ACF async |
| ITimelineReconstructor | Forensics | ICaseManagement | Internal |
| IChainOfCustody | Forensics | Evidence Audit Service | ACF append-only |
| ICaseManager | Forensics | SecurityWorker, Security Council | ACF sync |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Security.ForensicCaseOpened | New forensic case created | case_id, incident_ref, title, evidence_count |
| Security.EvidenceAcquired | Evidence successfully collected | evidence_id, case_id, type, hash, size_bytes, method |
| Security.EvidenceAnalyzed | Analysis completed for an evidence item | analysis_id, evidence_id, type, findings, iocs, confidence |
| Security.TimelineReconstructed | Full timeline built from correlated artifacts | case_id, event_count, time_span_start, time_span_end |
| Security.CaseClosed | Case analysis complete, ready for sealing | case_id, evidence_items, analysis_count, duration_hours |
| Security.ChainOfCustodyBroken | Hash mismatch or custody gap detected | case_id, evidence_id, expected_hash, actual_hash, sequence |
| Security.EvidenceCorrupted | Storage integrity check fails on evidence | evidence_id, case_id, stored_hash, computed_hash, action |
| Security.StorageLimitExceeded | Forensic storage allocation exceeded | case_id, current_bytes, limit_bytes, oldest_evidence |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SEC-FR-001 | Acquisition failure — source device not accessible | High | Halt acquisition, log error, request manual intervention |
| SEC-FR-002 | Evidence corruption — hash verification failed | Critical | Halt case, isolate corrupted evidence, attempt recovery from copy |
| SEC-FR-003 | Chain of custody break — missing or invalid entry | Critical | Halt analysis, investigate gap, document discrepancy |
| SEC-FR-004 | Storage allocation exceeded for forensic case | Medium | Archive oldest sealed cases, notify storage admin |
| SEC-FR-005 | Memory analysis — incompatible OS profile | Low | Try alternative profile, fall back to manual analysis |
| SEC-FR-006 | Timeline reconstruction — contradictory timestamps across evidence | Medium | Flag conflict, use confidence weighting, document anomaly |
| SEC-FR-007 | Write blocker verification failed | Critical | Abort acquisition, verify hardware, retry with confirmed blocker |
| SEC-FR-008 | Evidence already sealed — modification attempted | Critical | Reject modification, log attempt, escalate to Security Council |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SEC-FR-I-001 | Evidence acquisition uses write-protected methods only | Write-blocker verification before every acquisition operation |
| SEC-FR-I-002 | Every evidence item has cryptographically verified hash | SHA-256 computed at acquisition, verified before each analysis |
| SEC-FR-I-003 | Complete chain of custody maintained for every evidence item | Immutable append-only custody log with cross-hash chaining |
| SEC-FR-I-004 | Sealed evidence is immutable and cannot be modified | Cryptographic seal on case close, modification rejection |
| SEC-FR-I-005 | All forensic actions are logged with actor identity and timestamp | Mandatory audit log on every operation, schema enforcement |
| SEC-FR-I-006 | Original evidence is never modified — analysis uses verified copies | Copy-on-read analysis, write-protected originals |

## Design DNA

| Rule | Assessment |
|------|------------|
| R1 (Modulsingularity) | Acquisition, analysis, reconstruction, custody, sealing are separate modules |
| R2 (Capsule) | Each forensic case is an atomic capsule with evidence, timeline, and custody |
| R3 (Idempotent) | Same evidence and analysis toolset produces identical artifacts and hashes |
| R4 (Builder) | Case is built incrementally: open -> acquired -> analyzed -> reconstructed -> sealed |
| R5 (Manual Step) | Evidence sealing is a manual-gated operation — no auto-seal without review |
| R6 (No Orphans) | Every open case reaches sealed or closed status — no abandoned cases |
| R9 (Deterministic) | Same memory dump and profile yields identical process and connection lists |
| R10 (Event Sourcing) | Full case lifecycle reconstructable from forensic event log |
| R13 (Design for Failure) | Forensics fails safe — corrupted evidence never overwrites original |
| R14 (GC) | Sealed cases garbage collected after legal hold and retention period expire |
| R15 (Auth Chain) | Every custody transfer and analysis action links to authenticated actor |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Security/000-Overview.md | Overview — Forensics is a core Security capability |
| Bible/07-Domains/Security/001-Network-Scanning.md | Evidence — Network scan evidence ingested into forensic cases |
| Bible/07-Domains/Security/002-Vulnerability-Analysis.md | Evidence — Vulnerability analysis evidence feeds forensic timeline |
| Bible/04-Execution/Security/Audit/000-EAS.md | Audit — Evidence Audit Service integrates with chain of custody |
| Bible/04-Execution/Security/IDS/000-Overview.md | Identity — Forensic actor identity verification |
| Bible/04-Execution/Security/Crypto/000-CSP.md | Crypto — Cryptographic sealing and hash verification |
| Bible/04-Execution/Security/Crypto/001-CAM.md | Crypto — Certificate and key management for evidence signing |
| Bible/04-Execution/Security/CCA/000-CCA.md | Compliance — Chain of custody compliance auditing |
| Bible/08-Interfaces/SDK/001-Audit-SDK.md | Audit SDK — Forensic evidence audit integration |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — Core principles for evidence preservation |
